help_message="""Hey there! I'm a chat bot that's designed to help you troubleshoot those annoying AWS network problems
that are preventing you from connecting to your EC2 or RDS instances. Just by asking me a simple question,
or making a simple statement, you can give me enough information to go check the health of your instances
as well as your Network ACLs and Security Groups. Here are some examples:

USER> I cannot connect to my-awesome-ec2-server from my-other-awesome-ec2-server on port 22
or
USER> Help me connect to my-awesome-rds-instance from my-awesome-ec2-server on TCP port 5432
or
USER> Why can't I connect to my-awesome-rds-instance from my-other-awesome-ec2-server?
                
In any of your statements, you can specify the port you are trying to connect on, and even the IP protocol
you're trying to connect with. However, I'm pretty familiar with the standard ports (and even the ephemeral
ports!) for Linux servers, Windows servers, and most database types, so if you don't specify a port, I'll
take a stab at it. So let's start troubleshooting!!!"""