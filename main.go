package main

import (
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Forward struct {
	SrcHost  string
	SrcPort  int
	DestHost string
	DestPort int
}

type SSHRemote struct {
	Host     string
	Port     int
	Username string
}

var opts struct {
	RemoteForwards []string `short:"R" long:"remote" description:"Forward from remote"`
	LocalForwards  []string `short:"L" long:"local" description:"Forward to remote"`
	Identities     []string `short:"i" long:"identity" description:"Key files"`
}

var sshRemote SSHRemote
var localForwards []Forward
var remoteForwards []Forward

func main() {
	args, err := flags.Parse(&opts)

	if len(args) < 1 {
		log.Fatalf("Usage: tunnel-keeper [OPTIONS] <user@host>")
		return
	}

	sshRemote, err = parseSSHRemote(args[0])
	if err != nil {
		log.Fatalf("Failed to parse SSH remote: %v", err)
	}

	// Parse local forwards
	for _, str := range opts.LocalForwards {
		forward, err := parseForward(str)
		if err != nil {
			log.Fatalf("Failed to parse local forward: %v", err)
		}
		localForwards = append(localForwards, forward)
	}

	// Parse remote forwards
	for _, str := range opts.RemoteForwards {
		forward, err := parseForward(str)
		if err != nil {
			log.Fatalf("Failed to parse remote forward: %v", err)
		}
		remoteForwards = append(remoteForwards, forward)
	}

	retryAttempts := 0
	for {
		// Get the SSH agent
		sshAgent, err := getSSHAgent()
		if err != nil {
			log.Printf("Failed to get SSH agent: %v", err)
		}

		// Get the SSH client config
		config, port, err := getSSHConfig(sshRemote, sshAgent)
		if err != nil {
			log.Printf("Failed to get SSH client config: %v", err)
		}

		if dailSSH(fmt.Sprintf("%s:%d", sshRemote.Host, port), config) {
			retryAttempts = 0
		}

		// Calculate the next retry duration using exponential backoff
		retryDelay := math.Pow(2, float64(retryAttempts)) * 5 // seconds
		if retryDelay > 300 {
			retryDelay = 300 // cap at 5 minutes
		}
		log.Printf("Retrying in %d seconds...\n", int(retryDelay))
		time.Sleep(time.Duration(retryDelay) * time.Second)

		retryAttempts++
	}
}

func dailSSH(hostPort string, config *ssh.ClientConfig) bool {
	// Connect to SSH server
	conn, err := ssh.Dial("tcp", hostPort, config)

	if err != nil {
		log.Printf("Failed to connect to SSH server: %v", err)
		return false
	}

	//goland:noinspection GoUnhandledErrorResult
	defer conn.Close()

	wg := sync.WaitGroup{}

	for _, opt := range remoteForwards {
		wg.Add(1)
		go func(opt Forward) {
			defer wg.Done()
			// Start remote listener
			remoteListener, err := conn.Listen("tcp", fmt.Sprintf("%s:%d", opt.SrcHost, opt.SrcPort))
			if err != nil {
				log.Printf("Failed to start remote listener: %v", err)
				return
			}

			defer func(remoteListener net.Listener) {
				//goland:noinspection GoUnhandledErrorResult,GoDeferInLoop
				remoteListener.Close()
			}(remoteListener)

			log.Printf("Tunnel (S) %s:%d -> (L) %s:%d ", opt.SrcHost, opt.SrcPort, opt.DestHost, opt.DestPort)

			// Accept connections on remote listener
			for {
				remoteConn, err := remoteListener.Accept()
				if err != nil {
					log.Printf("Failed to accept incoming connection: %v", err)
					break
				}

				log.Printf("%s -> (S) -> (L) -> %s:%d", remoteConn.RemoteAddr(), opt.DestHost, opt.DestPort)

				// Start local forwarding
				go forwardRemote(remoteConn, fmt.Sprintf("%s:%d", opt.DestHost, opt.DestPort))
			}
		}(opt)
	}

	for _, opt := range localForwards {
		wg.Add(1)
		go func(opt Forward) {
			defer wg.Done()
			err := forwardLocal(opt, conn)
			if err != nil {
				log.Printf("Failed to listen on local: %v", err)
				return
			}
		}(opt)
	}

	wg.Wait()

	return true
}

func parseSSHRemote(info string) (SSHRemote, error) {
	// Split the info string into user, host, and port
	parts := strings.SplitN(info, "@", 2)
	if len(parts) == 1 {
		return SSHRemote{Host: parts[0], Port: -1, Username: ""}, nil // No username and default port
	} else if len(parts) == 2 {
		username := parts[0]
		hostPort := parts[1]
		port := -1 // default SSH port

		if strings.Contains(hostPort, ":") {
			host, portStr, err := net.SplitHostPort(hostPort)
			if err != nil {
				return SSHRemote{}, fmt.Errorf("failed to parse host:port: %v", err)
			}

			if portStr != "" {
				_, err := fmt.Sscanf(portStr, "%d", &port)
				if err != nil {
					return SSHRemote{}, fmt.Errorf("failed to parse port: %v", err)
				}
			}

			return SSHRemote{Host: host, Port: port, Username: username}, nil
		}

		return SSHRemote{Host: hostPort, Port: port, Username: username}, nil
	}

	return SSHRemote{}, fmt.Errorf("invalid format for SSH remote: %s", info)
}

func getSSHAgent() (agent.Agent, error) {
	// Check if SSH_AUTH_SOCK environment variable is set
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock != "" {
		// Connect to SSH agent
		agentConn, err := net.Dial("unix", sshAuthSock)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to SSH agent: %v", err)
		}

		// Create SSH agent client
		agentClient := agent.NewClient(agentConn)

		return agentClient, nil
	}

	return nil, nil
}

func getSSHConfig(sshRemote SSHRemote, sshAgent agent.Agent) (*ssh.ClientConfig, int, error) {
	// Check if SSH config file exists
	usr, err := user.Current()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get current user: %v", err)
	}

	var remote = sshRemote

	if remote.Port == -1 {
		portConfig := ssh_config.Get(sshRemote.Host, "Port")
		if portConfig != "" {
			_, err := fmt.Sscanf(portConfig, "%d", &remote.Port)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to parse port: %v", err)
			}
		} else {
			remote.Port = 22
		}
	}

	if remote.Username == "" {
		userConfig := ssh_config.Get(remote.Host, "User")
		if userConfig != "" {
			remote.Username = userConfig
		} else {
			remote.Username = usr.Username
		}
	}

	keyPaths := ssh_config.GetAll(remote.Host, "IdentityFile")

	if len(keyPaths) == 0 {
		keyPaths = []string{"~/.ssh/id_rsa"}
	}

	log.Printf("Using SSH user: %s", remote.Username)
	log.Printf("Using SSH host: %s", remote.Host)
	log.Printf("Using SSH port: %d", remote.Port)

	cfg, err := createConfig(remote.Username, keyPaths, usr.HomeDir, sshAgent)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create SSH config: %v", err)
	}

	return cfg, remote.Port, nil
}

func createConfig(sshUser string, keyPaths []string, homeDir string, sshAgent agent.Agent) (*ssh.ClientConfig, error) {
	var configSigners []ssh.Signer

	paths := append([]string{}, opts.Identities...)
	paths = append(paths, keyPaths...)

	for _, keyPath := range paths {
		if strings.HasPrefix(keyPath, "~/") {
			keyPath = filepath.Join(homeDir, keyPath[2:])
		}

		// Read the private key file
		privateKey, err := ioutil.ReadFile(keyPath)
		if err != nil {
			log.Printf("failed to read private key file: %v", err)
			continue
		}

		// Create a signer for the private key
		signer, err := ssh.ParsePrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}

		configSigners = append(configSigners, signer)
	}

	if sshAgent != nil {
		signers, err := sshAgent.Signers()
		if err != nil {
			return nil, fmt.Errorf("failed to get configSigners from SSH agent: %v", err)
		}

		signers = append(signers, configSigners...)

		// Create the client config with the SSH agent
		clientConfig := &ssh.ClientConfig{
			User: sshUser,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signers...),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		return clientConfig, nil
	}

	// Create the default client config
	clientConfig := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(configSigners...),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	return clientConfig, nil
}

func forwardLocal(fw Forward, client *ssh.Client) error {
	// Listen on local
	localListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", fw.SrcHost, fw.SrcPort))
	if err != nil {
		return fmt.Errorf("failed to listen on local port: %v", err)
	}

	//goland:noinspection GoUnhandledErrorResult
	defer localListener.Close()
	log.Printf("Tunnel (S) %s:%d <- (L) %s:%d ", fw.DestHost, fw.DestPort, fw.SrcHost, fw.SrcPort)

	for {
		// Accept local connections
		localConn, err := localListener.Accept()
		if err != nil {
			log.Printf("Failed to accept local connection: %v", err)
			//goland:noinspection GoUnhandledErrorResult
			localListener.Close()
			break
		}

		// Connect to remote address
		remoteConn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", fw.DestHost, fw.DestPort))
		if err != nil {
			log.Printf("Failed to connect to remote server: %v", err)
			//goland:noinspection GoUnhandledErrorResult
			localConn.Close()
			continue
		}

		log.Printf("(S) %s:%d <- (L) <- %s", fw.DestHost, fw.DestPort, localConn.RemoteAddr())

		go func() {
			_, _ = pipeTo(remoteConn, localConn)
			_ = localConn.Close()
			_ = remoteConn.Close()
		}()

		go func() {
			// Copy data between local and remote connections
			_, _ = pipeTo(localConn, remoteConn)
			_ = localConn.Close()
			_ = remoteConn.Close()
		}()
	}

	return nil
}

func forwardRemote(remoteConn net.Conn, localAddr string) {
	// Connect to local address
	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		log.Printf("Failed to connect to local server: %v", err)
		//goland:noinspection GoUnhandledErrorResult
		remoteConn.Close()
		return
	}

	//goland:noinspection GoUnhandledErrorResult
	defer localConn.Close()
	//goland:noinspection GoUnhandledErrorResult
	defer remoteConn.Close()

	// Copy data between remote and local connections
	go func() {
		_, _ = pipeTo(remoteConn, localConn)
	}()

	_, _ = pipeTo(localConn, remoteConn)
}

func pipeTo(dst net.Conn, src net.Conn) (int64, error) {
	var totalBytes int64

	buf := make([]byte, 0x4000)
	for {
		n, err := src.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return totalBytes, err
		}

		n, err = dst.Write(buf[:n])
		if err != nil {
			return totalBytes, err
		}

		totalBytes += int64(n)
	}

	return totalBytes, nil
}

func parseForward(str string) (Forward, error) {
	parts, err := splitParts(str)
	if err != nil {
		return Forward{}, err
	}

	if len(parts) < 2 || len(parts) > 4 {
		return Forward{}, fmt.Errorf("invalid format %s", str)
	}

	fw := Forward{}

	if len(parts) == 2 {
		_, err := fmt.Sscanf(parts[0], "%d", &fw.SrcPort)
		if err != nil {
			return Forward{}, fmt.Errorf("invalid format %s", str)
		}
		_, err = fmt.Sscanf(parts[1], "%d", &fw.DestPort)
		if err != nil {
			return Forward{}, fmt.Errorf("invalid format %s", str)
		}
		fw.SrcHost = "127.0.0.1"
		fw.DestHost = "127.0.0.1"
		return fw, nil
	}

	if len(parts) == 3 {
		_, err := fmt.Sscanf(parts[0], "%d", &fw.SrcPort)
		if err != nil {
			return Forward{}, fmt.Errorf("invalid format %s", str)
		}
		_, err = fmt.Sscanf(parts[2], "%d", &fw.DestPort)
		if err != nil {
			return Forward{}, fmt.Errorf("invalid format %s", str)
		}
		fw.SrcHost = "127.0.0.1"
		fw.DestHost = parts[1]
	}

	_, err = fmt.Sscanf(parts[1], "%d", &fw.SrcPort)
	if err != nil {
		return Forward{}, fmt.Errorf("invalid format %s", str)
	}
	_, err = fmt.Sscanf(parts[3], "%d", &fw.DestPort)
	if err != nil {
		return Forward{}, fmt.Errorf("invalid format %s", str)
	}
	fw.SrcHost = parts[0]
	fw.DestHost = parts[2]

	return fw, nil
}

// split string with colon, but ignore colon in square brackets
func splitParts(str string) ([]string, error) {
	var parts []string
	var part string
	var inBrackets bool

	for _, c := range str {
		if c == '[' {
			inBrackets = true
		} else if c == ']' {
			inBrackets = false
		} else if c == ':' && !inBrackets {
			parts = append(parts, part)
			part = ""
			continue
		}

		part += string(c)
	}

	if inBrackets {
		return nil, fmt.Errorf("invalid format %s", str)
	}

	if part != "" {
		parts = append(parts, part)
	}

	return parts, nil
}
