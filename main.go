package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"

	flags "github.com/jessevdk/go-flags"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Options is representing the command line argunments
type Options struct {
	Hostname           string `short:"H" long:"hostname" description:"The hostname to connect to" required:"true"`
	Port               int    `short:"P" long:"port" description:"SSH Port" default:"22"`
	User               string `short:"u" long:"username" description:"The Username to use" required:"true"`
	PassAuth           bool   `short:"a" long:"passwordauth" description:"use password authentication"`
	Password           string `short:"p" long:"password" description:"password to use"`
	IdentityFile       string `short:"i" long:"identityfile" description:"key to use. Will ignored if passwordauth is true" default:"~/.ssh/id_rsa"`
	Check              string `short:"c" long:"check" description:"the check to use" required:"true"`
	CheckArgs          string `short:"o" long:"options" description:"the check options" default:"local_plugins"`
	PluginFolder       string `short:"f" long:"pluginfolder" description:"the folder for the plugins to use" default:"./local_plugins"`
	RemotePluginFolder string `short:"r" long:"remotepluginfolder" description:"the remote plugin folder" default:"checks"`
}

var (
	opts       Options
	parser     = flags.NewParser(&opts, flags.Default)
	authMethod []ssh.AuthMethod
)

func getCheckFile(pluginFolder string, checkPlugin string) (checkFile string, err error) {
	checkFile, err = filepath.Abs(pluginFolder + "/" + checkPlugin)

	if _, err := os.Stat(checkFile); os.IsNotExist(err) {
		return "", fmt.Errorf("check %s does not exist", checkFile)
	}
	return
}

func checkOpts(opts *Options) error {
	if opts.PassAuth {
		if opts.Password != "" {
			return nil
		}
		return fmt.Errorf("You need to set a password for password auth")
	}
	if opts.IdentityFile == "" {
		return fmt.Errorf("You have to set an identity file")
	}
	if opts.IdentityFile == "~/.ssh/id_rsa" {
		user, _ := user.Current()
		dir := user.HomeDir
		opts.IdentityFile, _ = filepath.Abs(dir + "/.ssh/id_rsa")
	}

	if _, err := os.Stat(opts.IdentityFile); os.IsNotExist(err) {
		return fmt.Errorf("Identity file %s is not existing", opts.IdentityFile)
	}

	if _, err := getCheckFile(opts.PluginFolder, opts.Check); err != nil {
		return fmt.Errorf("error getting check file: %s", err)
	}
	return nil
}

func getPassauth(password string) (authMethod []ssh.AuthMethod) {
	return []ssh.AuthMethod{
		ssh.Password(opts.Password),
	}
}

func getCertAuth(identityFile string) (authMethod []ssh.AuthMethod, err error) {
	var signers []ssh.Signer
	if authsock := os.Getenv("SSH_AUTH_SOCK"); authsock != "" {
		sock, err := net.Dial("unix", authsock)
		if err != nil {
			return authMethod, err
		}

		agent := agent.NewClient(sock)

		signers, err = agent.Signers()
		if err != nil {
			return authMethod, err
		}
	} else {
		key, err := ioutil.ReadFile(identityFile)
		if err != nil {
			return authMethod, fmt.Errorf("unable to read private key: %v", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		signers = append(signers, signer)
		if err != nil {
			return authMethod, fmt.Errorf("unable to parse private key: %v", err)
		}
	}
	return []ssh.AuthMethod{
		ssh.PublicKeys(signers...),
	}, nil
}

func remoteCheckSum(conn *ssh.Client, targetFolder string, targetFile string) (checksum [16]byte, err error) {
	session, err := conn.NewSession()
	if err != nil {
		return checksum, fmt.Errorf("cant create session %s", err)
	}
	cmd := fmt.Sprintf("md5sum %s/%s", targetFolder, targetFile)
	output, err := session.Output(cmd)
	if err != nil {
		switch err.(type) {
		case *ssh.ExitError:
			err = fmt.Errorf("%s", output)
			return
		default:
			err = fmt.Errorf("unable to run command: %s", err)
			return
		}
	}
	decode, err := hex.DecodeString(string(output[:32]))

	if err != nil {
		return checksum, fmt.Errorf("hex decode error %s", err)
	}

	copy(checksum[:], decode[:16])

	return checksum, err
}

func copyCheck(conn *ssh.Client, targetFolder string, targetFile string, localFile string) (err error) {
	content, err := ioutil.ReadFile(localFile)
	if err != nil {
		return fmt.Errorf("can't read file %s", localFile)
	}

	localChecksum := md5.Sum(content)
	remoteChecksum, _ := remoteCheckSum(conn, targetFolder, targetFile)
	if localChecksum == remoteChecksum {
		return
	}
	session, err := conn.NewSession()

	if err != nil {
		return fmt.Errorf("cant create session %s", localFile)
	}
	go func() {
		w, _ := session.StdinPipe()
		defer w.Close()
		fmt.Fprintln(w, "D0750", 0, targetFolder)
		fmt.Fprintln(w, "C0740", len(content), targetFile)
		w.Write(content)
		fmt.Fprint(w, "\x00")
	}()
	if err := session.Run("scp -tr ./"); err != nil {
		return fmt.Errorf("Failed to run: %s", err)
	}
	session.Close()
	return
}

func main() {
	_, err := parser.Parse()
	if err != nil {
		fmt.Printf("UNKNWON - Error parsing argunments: %s\n", err)
		os.Exit(3)
	}
	err = checkOpts(&opts)
	if err != nil {
		fmt.Printf("UNKNOWN - Error in Options: %s\n", err)
		os.Exit(3)
	}

	if opts.PassAuth {
		authMethod = getPassauth(opts.Password)
	} else {
		authMethod, err = getCertAuth(opts.IdentityFile)
		if err != nil {
			fmt.Printf("UNKNOWN - error creating auth %s", err)
			os.Exit(3)
		}
	}

	config := &ssh.ClientConfig{
		User: opts.User,
		Auth: authMethod,
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", opts.Hostname, opts.Port), config)
	if err != nil {
		fmt.Printf("UNKNWON - unable to connect: %s", err)
		os.Exit(3)
	}

	localCheck, _ := getCheckFile(opts.PluginFolder, opts.Check)
	err = copyCheck(conn, opts.RemotePluginFolder, opts.Check, localCheck)
	if err != nil {
		fmt.Printf("UNKNOWN - copyCheck error %s", err)
		os.Exit(3)
	}

	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		fmt.Printf("UNKNOWN - unable to create session: %s", err)
		os.Exit(3)
	}

	if err != nil {
		fmt.Printf("UNKNOWN - copy error: %s", err)
		os.Exit(3)
	}
	args := ""

	if opts.CheckArgs != "" {
		args = " " + opts.CheckArgs
	}
	output, err := session.Output(opts.RemotePluginFolder + "/" + opts.Check + args)
	if err != nil {
		switch e := err.(type) {
		case *ssh.ExitError:
			fmt.Printf("%s", output)
			os.Exit(e.ExitStatus())
		default:
			fmt.Printf("UNKNOWN - unable to run command: %s", err)
			os.Exit(3)
		}
	}
	fmt.Printf("%s", output)
	defer session.Close()
	os.Exit(0)
}
