#file:          multissh.py
#description:   A tool for doing multiple ssh connections at one
#author:        @mastahyeti

from ssh_exceptions import *
from traceback import print_exc
from Queue import Queue,Empty
from copy import copy
from time import time
import paramiko
import threading
import socket
import random

# If people don't have scapy things wont work quite as well (testing is ssh is open)
try:
    SYN_SCAN = True
    from syn_scan import check_port
except ImportError,err:
    print "you are missing scapy, but I will let it slide this time: %s"%err
    SYN_SCAN = False
    from ping import check_host

DEBUG_LEVEL = 2

dont_care_about_pubs = paramiko.AutoAddPolicy()

def debug(message,level=1):
    if level <= DEBUG_LEVEL:
        print "##%d>  %s" % (level,str(message))

class Creds:
    '''
    set of credentials that can be easily iterated over, 
    returning tuples of (username,password,key) for
    every permutation. Each permutation includes either 
    a password or a key. These are presumably redundant
    '''
    def __init__(self):
        self.keys = []
        self.key_file_names = []
        self.usernames = []
        self.passwords = []

    def add_username(self,u):
        '''add username to our list'''
        self.usernames.append(u)

    def add_password(self,p):
        '''add a password to our list'''
        self.passwords.append(p)
    
    def add_key(self,k):
        '''add a paramiko private key object to our list'''
        self.keys.append(k)

    def add_rsa_key_file(self,kf):
        '''import a rsa private key from a keyfile'''
        k = paramiko.RSAKey.from_private_key_file(kf)
        self.keys.append(k)
        self.key_file_names.append(kf)
    
    def add_dsa_key_file(self,kf):
        '''import a dsa private key from a keyfile'''
        k = paramiko.DSAKey.from_private_key_file(kf)
        self.keys.append(k)
        self.key_file_names.append(kf)

    def get_usernames(self):
        '''return list of usernames'''
        return self.usernames

    def get_passwords(self):
        '''return list of passwords'''
        return self.passwords
    
    def get_keys(self):
        '''return list of private keys'''
        return self.keys

    def __iter__(self):
        return self._iterable()
    
    def _iterable(self):
        for u in self.usernames:
            for p in self.passwords:
                yield (u,p,None)
            for k in self.keys:
                yield (u,None,k)


class Commands:
    '''
    This stores a list of commands to be run. It also keeps track of their 
    outputs and allows for their output to be queried in a somewhat-nice way.
    '''
    def __init__(self):
        '''
        init 
        '''
        self.command_list = []
        self.output = {}

    def add_command(self,command,posthook=lambda output:output):
        '''
        add a command to be run 
            :command    - the command string to be run
            :posthook   - a function to be called with the output before it is returned.
                          this should take one argument (output) and return the modified
                          output.
        '''
        if command not in self.command_list:
            self.command_list  = [(command,posthook)] + self.command_list
            self.output[command] = {}

        else:
            print "duplicate command"

    def get_command_output(self,cmd):
        '''
        return the output of only the specified command (for use in cases of
        multiple commands being run)
            :cmd    - command for which output should be returned
        '''
        if cmd in self.output:
            out_str = ""
            for host in self.output[cmd]:
                out_str += "Host: %s\n"%host
                for line in self.output[cmd][host].split('\n'): out_str += "\t%s\n"%line
            return out_str
        else:
            return "that wasn't your last command"
    
    def get_host_output(self,host):
        '''
        return the output regarding only one host. it will return output from all commands 
        run on this host
            :host   - host for which output should be returned
        '''
        out = {}
        for cmd in self.output:
            if host in self.output[cmd]:
                out[cmd] = self.output[cmd][host]
        out_str = ""
        for cmd in out:
            out_str += "Command: %s\n" % cmd
            for line in out[cmd].split("\n"): out_str += "\t%s\n"%line
        if out_str == "": out_str = "you dont have that host"
        return out_str

    def generator(self):
        '''
        A generator function that will iterate over all commands. Once instantiated,
        this should be called for output with the send() command rather than the 
        next() command because you need to send the output of the previously run
        command.
        '''
        tmp_cmd_list = copy(self.command_list)
        while True:
            cmd,posthook = tmp_cmd_list.pop()
            host,output = yield(cmd)
            output = posthook(output)
            self.output[cmd][host] = output

            if not tmp_cmd_list: break

    def print_output(self):
        '''
        try to pretty_print the command output
        '''
        for command in self.output:
            print "Command: %s"%command
            for host in self.output[command]:
                print "\tHost:%s:"%host
                for line in self.output[command][host].split('\n'):
                    print "\t\t%s"%line


class SSHSession:
    '''
    This is a single connection to a single SSH server.
    This runs in its own thread.
    '''
    def __init__(self,host,die_event,command_queue,creds,port=22,disconnect_after=30):
        '''
        Create a new connection.
            :host               - DNS,netBIOS,IP address of host
            :die_event          - threading.Event() that tells us when to die 
            :command_queue      - Queue.Queue() that feeds us commands to run
            :creds              - mutlissh.Creds() object with authentication info
            :port               - TCP port the SSH server is running on
            :disconnect_after   - After how many seconds without new commands should the sessions be killed (for strealth)
        '''       
        debug("initting SSHSession",4)

        self.command_queue = command_queue

        self.host = host
        self.port = port

        self.creds = creds

        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(dont_care_about_pubs)

        self.username = None
        self.password = None
        self.key = None

        self.connected = False

        last_commands_time = time()
        while not die_event.is_set():
            try:
                #get some new commands to run from our queue
                commands = self.command_queue.get(block=True,timeout=.5)
                debug("Thread: %s got a commands"%self.host,4)
                #make sure that we are connected
                if not self._connect():
                    debug("Couldn't connect to host: %s"%self.host,2)
                #run the commands we were sent
                self._run(commands)
                #mark the task as done
                debug('marking task done',5)
                self.command_queue.task_done()
                #mark the time we finished so we know when we should kill our sessions
                last_commands_time = time()
            except Empty:
                #if we haven't received commands in a while, we can kill our sessions for now
                if self.connected and time() - last_commands_time >= disconnect_after: self._disconnect()

    def _run(self,commands):
        '''run through the Commands object'''
        debug("Running SSHSession.run",4)
        cmdgen = commands.generator()
        cmd = cmdgen.next()
        while True:
            try:
                stdin,stdout,stderr = self.ssh_client.exec_command(cmd)
                output = stdout.read()
                cmd = cmdgen.send((self.host,output))
            except StopIteration:
                break
    
    def _connect(self):
        '''This wraps around __connect to give a better interface'''
        debug("Running SSHSession._connect",4)
        if self.connected: return True
        debug("Connecting to host: %s"%self.host,2)
        self.connected = self.__connect()
        return self.connected

    def __connect(self):
        '''Do the actual work of trying to connect'''
        debug("Running SSHSession.__connect",4)
        alive = False
        try:
            if SYN_SCAN:
                alive = check_port(self.host,self.port)
                if alive: debug("Confirmed that port %d is listening on %s (syn scan)"%(self.port,self.host),2)
                else: 
                    debug("port %d is not listening on %s"%(self.port,self.host),1)
                    return False
            else:
                alive = check_host(self.host)
                if alive: debug("Confirmed that host %s is alive (ping)"%(self.host),2)
                else: debug("host %s may be dead (ping)"%(self.host),1)
            if not alive:
                debug("Host %s appears to be dead or port is closed"%self.host,1)
                return False
        except UnknownHost:
            debug("Host: %s is unknown..."%self.host,1)
            return False
        except NotRoot:
            debug("This tool will work better if run as root (can check if hosts are up)")



        try:
            #if we already have working username/password we will use them
            if self.username and self.password:
                try:
                    #if auth fails it raises an exception
                    self.ssh_client.connect(hostname=self.host,username=self.username,password=self.password,port=self.port)
                    debug("Succeeded connecting to host: '%s' with username %s and password '%s'"%(self.host,self.username,self.password),level=3)
                    return True
                except paramiko.AuthenticationException:
                    debug("Failed connecting to host: '%s' with username %s and password '%s'"%(self.host,self.username,self.password),level=2)
            
            #if we already have working username/privkey we will use them
            if self.username and self.key:
                try:
                    #if auth fails it raises an exception
                    self.ssh_client.connect(hostname=self.host,username=self.username,pkey=self.key,port=self.port)
                    debug("Succeeded connecting to host: '%s' with username %s and key '%s'"%(self.host,self.username,repr(self.key)),level=3)
                    return True
                except paramiko.AuthenticationException:
                    debug("Failed connecting to host: '%s' with username %s and key '%s'"%(self.host,self.username,repr(self.key)),level=2)

            #if we don't have working creds, we will iterate through known creds hoping to find something
            for (u,p,k) in self.creds:
                try:
                    #if auth fails it raises an exception
                    self.ssh_client.connect(hostname=self.host,username=u,password=p,pkey=k,port=self.port)
                    self.username = u
                    self.password = p
                    self.key = k
                    debug("Succeeded connecting to host: %s with username: '%s' password '%s'"%(self.host,u,repr([p,k][k is not None])),level=2)
                    return True
                except paramiko.AuthenticationException:
                    debug("Failed connecting to '%s' with username:'%s' and password '%s'"%(self.host,u,repr([p,k][k is not None])),level=3)

        except paramiko.SSHException,err:
            debug("Host '%s' appears to be dead: %s "%(self.host,str(err)))
            return False
        
        except socket.error,err:
            debug("Host '%s' appears to be dead:%s"%(self.host,str(err)))
            return False

        debug("Couldn't connect to host: '%s' with any credentials"%self.host)
        return False

    def _disconnect(self):
        '''Disconnect from the server'''
        debug("Running SSHSession._disconnect",4)
        if self.connected:
            debug("Disconnecting from host: %s"%self.host,2)
            self.ssh_client.close()
            self.connected = False        


class MultiSSH:
    '''An SSH Client for handling multiple hosts simultaniously'''
    def __init__(self,print_output=True):
        '''
        Create a MultiSSH instance
            :print_output       - Bool determining if command output is printed
        '''
        debug("Running MultiSSH",4)

        self.print_output = print_output
        self.creds = Creds()
        self.hosts = {}
    
    def run(self,commands,hosts=None):
        '''
        run the specified command. 
            :command    - command(s) to run. can be singe command (string) or multiple (list)
            :hosts      - if specified, command will only run on these hosts. Can be list or string
        '''
        debug("Running MultiSSH.run",4)

        # if they gave a str, we need a list
        if type(commands) == str: commands = [commands]
        # make new Commands object
        self.commands = Commands()
        # add the users commands to our Commands
        [self.commands.add_command(c) for c in commands]
        # add our Commands to our sesionss' queues
        self._add_to_queues(self.commands,hosts)
        # wait for responses
        debug("Joining command queues",4)
        self._join_queues(hosts)

        #they might have asked us to print command outputs
        if self.print_output: self.commands.print_output()

        return self.commands

    def add_host(self,hostname,port=22):
        '''
        Add a new host
            :hostname       - DNS,NetBIOS, or IP Address of the host
            :port           - TCP port that the SSH server is running on
        '''
        debug("Running MultiSSH.add_host",4)

        kwargs = {\
            'host':             hostname,\
            'die_event':        threading.Event(),\
            'command_queue':    Queue(),\
            'creds':            self.creds,
            'port':             port}

        thread = threading.Thread(target=SSHSession,name=hostname,kwargs=kwargs)
        thread.daemon = False
        thread.start()
        kwargs['thread'] = thread
        self.hosts[hostname] = kwargs

    def get_hosts(self):
        '''
        return list of hosts
        '''
        return self.hosts

    def kill(self):
        '''
        kill all connections. You must call this before exiting.
        '''
        [self.hosts[host]['die_event'].set() for host in self.hosts]
    
    def _add_to_queues(self,commands,hosts=None):        
        '''
        add commands to hosts' queues
            :commands   - commands to add to the queues. This should be a Commands object
            :hosts      - if specified, command will only run on these hosts. Can be list or string
        '''
        debug("Running MultiSSH._add_to_queues",5)

        if not hosts: hosts = self.hosts.keys()
        if type(hosts) == str: hosts = [host]
        [self.hosts[host]['command_queue'].put(commands) for host in hosts]

    def _join_queues(self,hosts=None):
        '''
        join all hosts' queues
            :hosts      - if specified, we will only join the queues of the specified hosts
        '''
        debug("Running MultiSSH._join_queues",5)

        if not hosts: hosts = self.hosts.keys()
        queues = [self.hosts[host]['command_queue'] for host in hosts]
        [q.join() for q in queues]

    '''Wrapping arround the Creds object'''
    def add_username(self,username):
        self.creds.add_username(username)
    def add_password(self,password):
        self.creds.add_password(password)
    def add_rsa_key_file(self,filename):
        self.creds.add_rsa_key_file(filename)
    def add_dsa_key_file(self,filename):
        self.creds.add_dsa_key_file(filename)


class UI():
    '''A menu driven user interface. Instantiating this will launch it'''
    def __init__(self):
        self.config = {\
            'hosts': {\
                'description':'The hosts that we will be trying to connect to',\
                'value':[]},\
            'port': {\
                'description':'The port on the hosts that we will connect to.',\
                'value':22},\
            'usernames': {\
                'description':'The usernames that we are going to try to connect with',\
                'value':[]},\
            'passwords': {\
                'description':'The passwords that we are going to try to connect with',\
                'value':[]},\
            'rsa_keyfiles': {\
                'description':'RSA key files that we can try to connect with',\
                'value':[]},\
            'dsa_keyfiles': {\
                'description':'DSA key files that we can try to connect with',\
                'value':[]},\
            'command_batch': {\
                'description':'batch of commands to be run with the `run` command',\
                'value':[]}}
        
        #parse the functions in this class to figure out command names and descriptions
        self.commands = self._get_commands()

        self.multi_ssh = MultiSSH()
        try:
            self._main()
        except Exception,err:
            self.multi_ssh.kill()
            print_exc()
            self.quit()
    
    def _sync_configs(self):
        # hosts
        for host in self.config['hosts']['value']:
            if host not in self.multi_ssh.hosts:
                self.multi_ssh.add_host(hostname=host,port=self.config['port']['value'])
        for host in self.multi_ssh.hosts:
            if host not in self.config['hosts']['value']:
                self.multi_ssh.hosts[host]['die_event'].set()
                del(self.multi_ssh.hosts[host])
        
        # usernames
        for username in self.config['usernames']['value']:
            if username not in self.multi_ssh.creds.usernames:
                self.multi_ssh.add_username(username)
        
        for username in self.multi_ssh.creds.usernames:
            if username not in self.config['usernames']['value']:
                while self.multi_ssh.creds.usernames.count(username) > 1:
                    self.multi_ssh.creds.usernames.remove(username)

        # passwords
        for password in self.config['passwords']['value']:
            if password not in self.multi_ssh.creds.passwords:
                self.multi_ssh.add_password(password)
        
        for password in self.multi_ssh.creds.passwords:
            if password not in self.config['passwords']['value']:
                while self.multi_ssh.creds.passwords.count(password) > 1:
                    self.multi_ssh.creds.passwords.remove(password)
                    
        # rsa
        for rsa in self.config['rsa_keyfiles']['value']:
            if rsa not in self.multi_ssh.creds.key_file_names:
                self.multi_ssh.add_rsa_key_file(rsa)

        # dsa
        for dsa in self.config['dsa_keyfiles']['value']:
            if dsa not in self.multi_ssh.creds.key_file_names:
                self.multi_ssh.add_dsa_key_file(dsa)
        
    def _run(self,c):
        self._sync_configs()
        self.last_command = self.multi_ssh.run(c)
        return True

    def delete(self,string):
        '''
        delete one or several configuration parameters
        Eg.
            multi> delete username root
            multi> delete hosts localhost 127.0.0.1 example.com 
        '''
        parm = string.split(" ")[0]
        vals = string.split(" ")[1:]

        for val in vals:
            try:
                if type(self.config[parm]['value']) == list:
                    while True:
                        try:
                            self.config[parm]['value'].remove(val)
                        except ValueError:
                            break
                else:
                    print "not quite sure how to delete this. its an error!!!"
            except KeyError:
                print "couldn't delete config[%s][%s]. It doesn't exist..." % (parm,val)
        self._sync_configs()
        return True

    def set(self,mystring):
        '''
        set a configuration parameter. 
        Eg.
            multi> set port=22
            multi> set command_batch=['ls','whoami','cat /etc/passwd']
        '''
        try:
            # backup and delete our needed local vars
            globals()['__tmp_self__'] = self
            globals()['__tmp_mystring__'] = mystring
            del(self,mystring)
            
            # exec our string in the local context
            exec __tmp_mystring__

            # copy ALL local context vars into self.mydict
            [__tmp_self__.config.setdefault(__k__,{'value':'','description':''}) for __k__,__v__ in locals().items()]
            del(__k__,__v__)
            [__tmp_self__.config[__k__].__setitem__("value",__v__) for __k__,__v__ in locals().items()]
            
            # cleanup the mess we made of the globals
            self = globals()["__tmp_self__"]
            del(globals()["__tmp_self__"])
            del(globals()["__tmp_mystring__"])
            self._sync_configs()
        except:
            print "Something went wrong. Bad syntax probably. You should be using Python syntax."
        return True
    
    def get(self,string):
        '''
        get the results of the last run command
        by host or by command (for command_batches)
        Eg.
            multi> get host 127.0.0.1               #returns results from 127.0.0.1
            multi> get host 127.0.0.1 example.com   #returns results from 127.0.0.1 and example.com
            multi> get command ls                   #returns results of command ls from all hosts (only works with command_batches)
        '''
        q = string.split(" ")[0]
        d = string.split(" ")[1:]
        for x in d:
            print [self.last_command.get_host_output,self.last_command.get_command_output][q=="command"](x)
        
        return True


    def add(self,string):
        '''
        add a value to a configuration option.
        Eg.
            multi> add host 127.0.0.1
            multi> add usernames root mastahyeti
        '''
        parm = string.split(' ')[0]
        vals = string.split(' ')[1:]
        if parm == "command_batch":
            vals = [" ".join(vals)]

        for val in vals:
            if val not in self.config[parm]:
                self.config[parm]['value'].append(val)
        self._sync_configs()
        return True

    def run(self,string):
        '''
        run the batch of commands set in the command_batch configuration 
        parameter. You can then get the results with the get command
        Eg.
            multi> run
        '''
        self._run(self.config['command_batch']['value'])
        
    
    def help(self,string=""):
        '''
        print this message
        '''
        print "==Help==\n\nWelcome to MultiSSH. Usage is pretty simple. You can set\nparameters with the 'set' command, add values to parameter\nlists with the 'add' command, inspect current settings\nwith the 'show' command. If you type an unrecognized command,\nit will be assumed that you meant for that command to be run \non all of the SSH sessions. If you configure the 'command_batch'\nparameter you can run multiple commands at once and then\nuse the 'get' command to query their output by host\nor by command.\n\n Here is a bit more info about each command.\n"
        for command in self.commands:
            print "%s\t\t%s" % (command,self.commands[command])
        
        return True
    
    def show(self,foobar=""):
        '''
        show all or some of the config parameters
        Eg. (shows whole config)
            multi> show
            multi> show hosts
        '''
        print "==Configuration Parameters=="
        keys = self.config.keys()

        if foobar in keys:
            keys = [foobar]

        for key in keys:
            print "\t%s : %s" % (key,str(self.config[key]['value']))
            if 'description' in self.config[key]:
                print "\tDescription: %s" % self.config[key]['description']
            print "\n"

        return True

    def quit(self,str=""):
        '''
        exit MultiSSH
        '''
        print "goodbye..."
        self.multi_ssh.kill()
        quit()
    
    def mandelbrot(self,string=''):
        '''
        pint a mandelbrot       
        '''
        #credit: http://warp.povusers.org/MandScripts/python.html        

        minX = -1.5
        maxX = .8
        width = 117
        height = 54
        aspectRatio = 2

        chars = " .,-:;i+hHM$*#@ "

        yScale = (maxX-minX)*(float(height)/width)*aspectRatio

        rval = ""

        for y in range(height):
            line = ""
            for x in range(width):
                c = complex(minX+x*(maxX-minX)/width, y*yScale/height-yScale/2)
                z = c
                for char in chars:
                    if abs(z) > 2:
                        break
                    z = z*z+c
                line += char
            rval += line + "\n"
        if string != "noprint":
            print rval
        else:
            return rval
    
    def _get_commands(self):
        commands = {}
        names = filter(lambda name: name[0] != "_" and callable(getattr(self,name)),dir(self))
        map(lambda name:commands.setdefault(name,getattr(self,name).__doc__),names)
        return commands

    def _main(self):
        '''main REPL loop'''
        print "\n" * 100
        logo = '***MULTISSH***'
        cow = " ________________\n< MultiSSH! >\n ----------------\n        \   ^__^\n         \  (oo)\_______\n            (__)\       )\/\\\n                ||----w |\n                ||     ||"
        mb = self.mandelbrot('noprint')
        print random.choice([logo,mb,cow])        
        print "\nWelcome to MultiSSH. Type 'help' if you don't know what you are doing.\n\n"
        
        dont_stop = True
        while dont_stop != False:
            #get command
            raw_command = raw_input("multi> ")

            #parse command
            parts = raw_command.split(" ")
            command = parts[0]
            if len(parts) > 1: args = ' '.join(parts[1:])
            else: args = ""

            if command in self.commands:
                dont_stop = getattr(self,command)(args)
            else:
                if args != "": command += " " + args
                self._run(command)        


if __name__ == "__main__":
    my_ui = UI()