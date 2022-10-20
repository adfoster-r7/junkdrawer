require "reline"
require "optionparser"

class String
  def red
    "\e[0;31m#{self}\e[0m"
  end

  def yellow
    "\e[0;33m#{self}\e[0m"
  end

  def blue
    "\e[0;34m#{self}\e[0m"
  end

  def green
    "\e[0;32m#{self}\e[0m"
  end

  def cyan
    "\e[0;36#{self}\e[0m"
  end

  def underscore
    "\e[4m#{self}\e[0m"
  end
end

class SmbInteraction
  def self.ls(connection, share, pwd)
    if !share
      "#{'[!]'.red} No share currently selected"
    elsif pwd == "/"
      <<~FILES.lines
        40755/rwxr-xr-x   928     dir   2020-08-18 14:22:23 +0100  foo
      FILES
    elsif pwd == "/foo"
      <<~FILES.lines
        100644/rw-r--r--  1075    fil   2020-03-09 22:05:29 +0000  CURRENT.md
        100644/rw-r--r--  2336    fil   2020-06-25 00:15:47 +0100  Dockerfile
      FILES
    end
  end

  def self.shares(connection)
    <<~VERSION
      #{"[!]".red} 127.0.0.1:445         - peer_native_os is only available with SMB1 (current version: SMB3)
      #{"[!]".red} 127.0.0.1:445         - peer_native_lm is only available with SMB1 (current version: SMB3)
      #{"[+]".green} 127.0.0.1:445         - Administrators Public Folder - (DISK)
      #{"[+]".green} 127.0.0.1:445         - impacket - (DISK)
      #{"[+]".green} 127.0.0.1:445         - IPC$ - (IPC)
    VERSION
  end

  def self.version(connection)
    <<~VERSON
      #{"[*]".blue} #{@ip}:445         - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.0.2) (signatures:optional) (guid:{456d7474-b802-0154-93bf-cadc196be2f9}) (authentication domain:BFS-MBP-6679)
    VERSON
  end
end

class SmbConnection
  def initialize(opts)
    # ...
  end

  def close
    # ...
  end

  def self.connect(rhost, &block)
    connection = self.new({ rhost: rhost })
    block.call(connection)
  ensure
    connection.close
  end
end

class MockSession
  attr_accessor :connection_string
  attr_accessor :ip
  attr_accessor :info
  attr_accessor :type
  # This will need to remember your state when you switch between shares most likely
  attr_accessor :active_share
  attr_accessor :active_share_pwd

  def prompt
    if active_share
      "#{ip.red}/#{active_share}#{active_share_pwd}"
    else
      "#{ip.red}"
    end
  end

  def ls
    SmbInteraction.ls(connection, active_share, active_share_pwd)
  end

  def version
    SmbInteraction.version(connection)
  end

  def shares
    SmbInteraction.shares(connection)
  end

  def connection
    # Mock connection for now
    nil
  end
end



class MockState
  attr_accessor :in_smb
  attr_accessor :closed
  attr_reader :sessions
  attr_reader :active_session
  attr_reader :datastore

  def initialize
    @sessions = []
    @active_session = nil
    @active_session_index = nil
    @datastore = {}
  end

  def current_prompt
    if @active_session
      "#{"smb".underscore}(#{@active_session.prompt}) > "
    elsif in_smb
      "#{"msf6".underscore} auxiliary(#{"auxiliary/client/smb".red})> "
    else
      "#{"msf6".underscore} > "
    end
  end

  def open_session(value)
    @active_session_index = value == -1 ? @sessions.length - 1 : value
    @active_session = sessions[@active_session_index]

    puts "#{'[*]'.blue} Starting interaction with #{@active_session_index}..."
    puts
  end

  def register_session(session)
    @sessions << session
    puts "#{'[*]'.blue} #{session.type} Session #{@sessions.length} opened (#{session.info}) at #{Time.now}"
  end

  def background_session
    puts "#{'[*]'.blue} Background Session #{@active_session_index}"

    @active_session_index = nil
    @active_session = nil
  end

end

def create_mock_session
  mock_session = MockSession.new
  mock_session.active_share = nil
  mock_session.active_share_pwd = nil
  mock_session.ip = "127.0.0.1"
  mock_session.type = "SMB"
  mock_session.info = "foo:bar@127.0.0.1"
  mock_session
end

=begin

TODO:
  - Blue related exploits
    - Take inspiration from scripts/resource/smb_checks.rc ?
    - getsystem (???)
  - Post modules - we can ignore this for now. This doesn't exist just yet.
  - Can we reuse a module entirely for this functionality? With enhanced actions support?

Workflows:

Uploading/Downoading arbitrary files without needing to go via a session:
  smb> upload RHOST=127.0.0.1 SmbPass=abc Smbuser=abc file=foo
  smb> download RHOST=127.0.0.1 SmbPass=abc Smbuser=abc file=/foo/bar/baz

Creating sessions:
  smb> login foo:bar@127.0.0.1
  [*] SMB Session 1 opened (foo:bar@127.0.0.1) at 2020-08-27 14:02:40 +0100
  smb> login RHOST=127.0.0.1 smbpass=abc smbuser
  smb> login RHOST=10.0.0.0/16 smbpass=abc smbuser
  [*] SMB Session 1 opened (foo:bar@10.0.0.1) at 2020-08-27 14:02:40 +0100
  [*] SMB Session 2 opened (foo:bar@10.0.0.2) at 2020-08-27 14:02:40 +0100
  [*] SMB Session 3 opened (foo:bar@10.0.0.3) at 2020-08-27 14:02:40 +0100

Brute forcing users:
   smb> set RHOST_SMB_URL foo:bar@127.0.0.1
   smb> users

Brute forcing users:
   smb> set RHOST_SMB_URL foo:bar@127.0.0.1
   smb> users

Creating a listening server:
  smb> capture -h
  smb> capture SRVHOST=tun1

Interacting with a session, and performing additional enumeration:
  smb > login foo:bar@127.0.0.1
  [*] SMB Session 1 opened (foo:bar@127.0.0.1) at 2020-08-27 14:02:40 +0100
  smb > sessions -i -1
  [*] Starting interaction with 0...

  smb(127.0.0.1/) > shares
  [!] 127.0.0.1:445         - peer_native_os is only available with SMB1 (current version: SMB3)
  [!] 127.0.0.1:445         - peer_native_lm is only available with SMB1 (current version: SMB3)
  [+] 127.0.0.1:445         - Administrators Public Folder - (DISK)
  [+] 127.0.0.1:445         - impacket - (DISK)
  [+] 127.0.0.1:445         - IPC$ - (IPC)
  smb(127.0.0.1/) > cd foo
  smb(127.0.0.1/foo) > cd foo

Extra needed effort:
   - Tab completion of command options. This isn't currently supported, even within
      a module: `msf6 auxiliary(foo) > run RHO<tab>`
  - Verify that the current options support allows strings etc to ensure flags aren't
    set unexpectedly. For instance in the scenario of a flag `-j` being in a password:
      `run SmbPass="i-love-jam"`

Unsure:
  Will there be a command for every variation? For instance crackmapexec uses flags:
    - cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --groups
    - cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --local-groups
    - cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --pass-pol
=end
def command_mapping
  {
    'use auxiliary/client/smb' => proc do |state, _command|
      state.in_smb = true
    end,
    'exit' => proc do |state, _command|
      state.closed = true
    end,
    'sessions' => proc do |state, _command|
      sessions = state.sessions

      puts "Mock Sessions"
      puts "============="

      puts "Id    Name  Type   Information"
      puts "--    ----  ----   -----------"
      sessions.each_with_index do |session, index|
        puts "#{index}           #{session.type}    #{session.info}"
      end
      puts
    end,
    'sessions -i -1' => proc do |state, _command|
      state.open_session(-1)
    end,
    'help' => proc do |state, _command|
      puts <<~SHARE_OPTIONS.lines.map { |x| "  #{x}" }
        Core Commands
        =============

            Command       Description
            -------       -----------
            help          Help menu
            set           Set options

        Stdapi: File system Commands
        ============================

            Command       Description
            -------       -----------
            cat           Read the contents of a file to the screen
            cd            Change directory
            checksum      Retrieve the checksum of a file
            chmod         Change the permissions of a file
            cp            Copy source to destination
            del           Delete the specified file
            dir           List files (alias for ls)
            download      Download a file or directory
            edit          Edit a file
            getlwd        Print local working directory
            getwd         Print working directory
            lcd           Change local working directory
            lls           List local files
            lpwd          Print local working directory
            ls            List files
            mkdir         Make directory
            mv            Move source to destination
            pwd           Print working directory
            rm            Delete the specified file
            rmdir         Remove directory
            upload        Upload a file or directory

        Auxiliary: Commands
        =============
            login         Attempt to log in to smb
            shares        List the shares
            users         List the available users
            version       Fingerprint the smb version of the rhost
            secretsdump   Dumps SAM hashes and LSA secrets from Windows machine

      SHARE_OPTIONS
    end,
    ################################################
    # Generic smb commands
    ################################################
    'login foo:bar@127.0.0.1' => proc do |state, _command|
      state.register_session(create_mock_session)
    end,
    # 'login'
    'version' => proc do |state, _command|
      puts state.active_session.version
    end,
    'shares' => proc do |state, _command|
      puts state.active_session.shares
    end,
    'shares RHOST=127.0.0.1' => proc do |state, _command|
      SmbConnection.connect('127.0.0.1') do |connection|
        puts SmbInteraction.shares(connection)
      end
    end,
    'set RHOST 127.0.0.1' => proc do |state, _command|
      state.datastore['RHOST'] = '127.0.0.1'
      puts 'RHOST => 127.0.0.1'
    end,
    'set' => proc do |state, _command|
      pp state.datastore
    end,
    'run RHOST=' => proc do |state, _command|

    end,
    'login -h' => proc do |state, _command|
      puts "Options"

      puts <<~SHARE_OPTIONS.lines.map { |x| "  #{x}" }

        Name               Current Setting  Required  Description
        ----               ---------------  --------  -----------
        ABORT_ON_LOCKOUT   false            yes       Abort the run when an account lockout is detected
        BLANK_PASSWORDS    false            no        Try blank passwords for all users
        BRUTEFORCE_SPEED   5                yes       How fast to bruteforce, from 0 to 5
        DB_ALL_CREDS       false            no        Try each user/password couple stored in the current dat
                                                      abase
        DB_ALL_PASS        false            no        Add all passwords in the current database to the list
        DB_ALL_USERS       false            no        Add all users in the current database to the list
        DETECT_ANY_AUTH    false            no        Enable detection of systems accepting any authenticatio
                                                      n
        DETECT_ANY_DOMAIN  false            no        Detect if domain is required for the specified user
        PASS_FILE                           no        File containing passwords, one per line
        PRESERVE_DOMAINS   true             no        Respect a username that contains a domain name.
        Proxies                             no        A proxy chain of format type:host:port[,type:host:port]
                                                      [...]
        RECORD_GUEST       false            no        Record guest-privileged random logins to the database
        RHOSTS             127.0.0.1        yes       The target host(s), range CIDR identifier, or hosts fil
                                                      e with syntax 'file:<path>'
        RPORT              445              yes       The SMB service port (TCP)
        SMBDomain          .                no        The Windows domain to use for authentication
        SMBPass            test             no        The password for the specified username
        SMBUser            test             no        The username to authenticate as
        STOP_ON_SUCCESS    false            yes       Stop guessing when a credential works for a host
        THREADS            1                yes       The number of concurrent threads (max one per host)
        USERPASS_FILE                       no        File containing users and passwords separated by space,
                                                       one pair per line
        USER_AS_PASS       false            no        Try the username as the password for all users
        USER_FILE                           no        File containing usernames, one per line
        VERBOSE            true             yes       Whether to print output for all attempts
      SHARE_OPTIONS
    end,
    'shares -h' => proc do |state, _command|
      puts "Options"

      puts <<~SHARE_OPTIONS.lines.map { |x| "  #{x}" }
        Name            Current Setting  Required  Description
        ----            ---------------  --------  -----------
        LogSpider       3                no        0 = disabled, 1 = CSV, 2 = table (txt), 3 = one liner (txt
                                                   ) (Accepted: 0, 1, 2, 3)
        MaxDepth        999              yes       Max number of subdirectories to spider
        RHOSTS          127.0.0.1        yes       The target host(s), range CIDR identifier, or hosts file w
                                                   ith syntax 'file:<path>'
        SMBDomain       .                no        The Windows domain to use for authentication
        SMBPass         test             no        The password for the specified username
        SMBUser         test             no        The username to authenticate as
        ShowFiles       false            yes       Show detailed information when spidering
        SpiderProfiles  true             no        Spider only user profiles when share = C$
        SpiderShares    false            no        Spider shares recursively
        THREADS         1                yes       The number of concurrent threads (max one per host)
      SHARE_OPTIONS
    end,

    ################################################
    # Session specific commands
    ################################################
    'background' => proc do |state, _command|
      state.background_session
    end,
    'use_share impacket' => proc do |state, _command|
      state.active_session.active_share = 'impacket'
      state.active_session.active_share_pwd = '/'
    end,
    'cd foo' => proc do |state, _command|
      state.active_session.active_share_pwd = File.join(state.active_session.active_share_pwd, "foo")
    end,
    'cd /' => proc do |state, _command|
      state.active_session.active_share_pwd = "/"
    end,
    'ls' => proc do |state, _command|
      puts "Mock ls"
      puts "============="
      puts
      puts "Mode              Size    Type  Last modified              Name"
      puts "----              ----    ----  -------------              ----"

      files = state.active_session.ls
      files.each do |file|
        puts file
      end
    end
  }
end

def parse_options(state, input)
  command = input.strip

  handler = command_mapping[command]
  handler&.call(state, command)

  state
end


def readline_completion
  proc do |s|
    puts "-> #{Reline.completion_append_character.inspect}"
    # puts Readline.completion_append_character = ('a'.ord + (0..20).to_a.sample).chr


    command_mapping
      .keys
      .reject { |value| value =~ /-h/ }
      .grep(/^#{Regexp.escape(s)}/)
  end
end


# set RH<tab>
# set RHOST= <cursor>

def main
  state = MockState.new
  state.register_session(create_mock_session)
  state.open_session(-1)

  Reline.completion_proc = readline_completion
  Reline.basic_word_break_characters = ""

  while input = Reline.readline(state.current_prompt, true)
    state = parse_options(state, input)

    exit if state.closed
  end
end

main
