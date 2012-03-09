#MultiSSH#
##Author:##
@mastahyeti
##Description:##
this is a tool for running multiple SSH connections at the same time. This application works best if run as root. It also works best if you have scapy installed. That beings said, it can work without either of those requirements.
##Dependencies##

Required:

    *python2.7   -- Weird bugs in 2.6. Haven't tried 3.0
    *paramiko    -- SSH Library in pure python

Optional:

    *scapy       -- Packet crafting. allows me to syn scan hosts before trying to connect (make sure they're live...)
    
##Usage:##
To start MultiSSH, type:
    sudo python ./multissh.py

Once you have launched it, type `help` to see the available commands.

##Commands##
Here are the contents of the help command:

    Welcome to MultiSSH. Usage is pretty simple. You can set
    parameters with the 'set' command, add values to parameter
    lists with the 'add' command, inspect current settings
    with the 'show' command. If you type an unrecognized command,
    it will be assumed that you meant for that command to be run 
    on all of the SSH sessions. If you configure the 'command_batch'
    parameter you can run multiple commands at once and then
    use the 'get' command to query their output by host
    or by command.
    
     Here is a bit more info about each command.
    
    quit    	
            exit MultiSSH
            
    set		
            set a configuration parameter. 
            Eg.
                multi> set port=22
                multi> set command_batch=['ls','whoami','cat /etc/passwd']
            
    run		
            run the batch of commands set in the command_batch configuration 
            parameter. You can then get the results with the get command
            Eg.
                multi> run
            
    help		
            print this message
            
    get		
            get the results of the last run command
            by host or by command (for command_batches)
            Eg.
                multi> get host 127.0.0.1               #returns results from 127.0.0.1
                multi> get host 127.0.0.1 example.com   #returns results from 127.0.0.1 and example.com
                multi> get command ls                   #returns results of command ls from all hosts (only works with command_batches)
            
    show		
            show all or some of the config parameters
            Eg. (shows whole config)
                multi> show
                multi> show hosts
            
    mandelbrot		
            pint a mandelbrot       
            
    add		
            add a value to a configuration option.
            Eg.
                multi> add host 127.0.0.1
                multi> add usernames root mastahyeti
            
    delete		
            delete one or several configuration parameters
            Eg.
                multi> delete username root
                multi> delete hosts localhost 127.0.0.1 example.com 


##Issues:##
Hit me up on github if there are any issues. Also feel free to submit issues. I Probably wont respond to either....


