import netaddr
import logging
import boto3
import json
import sys
import re


logfile = "check_aws_network.log"
logging_level = 'DEBUG'
numeric_level = getattr(logging, logging_level.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: {}'.format(logging_level))

logging.basicConfig(filename=logfile, filemode='w', format='%(asctime)s | %(levelname)-8s | %(funcName)-15s | %(message)s', datefmt='%H:%M:%S', level=numeric_level)


def troubleshoot(source_name,destination_name,port=None,source_type='UNKNOWN',destination_type='UNKNOWN',ip_protocol='tcp'):
    proceed = True
    source_metadata = get_instance_metadata(source_name,source_type)
    if 'error_type' in source_metadata:
        print("Uh oh, something went wrong getting metadata for {}!\n{}\n{}".format(source_name,source_metadata['error_type'],source_metadata['error_msg']))
        proceed = False
    else:
        print("\nMetadata for {}\n{}\n".format(source_name,source_metadata))
    destination_metadata = get_instance_metadata(destination_name,destination_type)
    if 'error_type' in destination_metadata:
        print("Uh oh, something went wrong getting metadata for {}!\n{}\n{}".format(destination_name,destination_metadata['error_type'],destination_metadata['error_msg']))
        proceed = False
    else:
        print("\nMetadata for {}\n{}\n".format(destination_name,destination_metadata))
    #
    # Use default ports if no port passed in
    if proceed:
        if not port:
            if destination_metadata['instance_type'] == 'EC2':
                if destination_metadata['platform'].lower() == 'linux':
                    port = 22
                elif destination_metadata['platform'].lower() == 'windows':
                    port = 3389
                else:
                    print("I do not know the default port for the platform: {}".format(destination_metadata['platform']))
                    proceed = False
            elif destination_metadata['instance_type'] == 'RDS':
                if re.search(r"oracle",destination_metadata['engine'],re.IGNORECASE):
                    port = 1521
                elif re.search(r"[mysql|aurora|mariadb]",destination_metadata['engine'],re.IGNORECASE):
                    port = 3306
                elif re.search(r"postgres",destination_metadata['engine'],re.IGNORECASE):
                    port = 5432
                elif re.search(r"sqlserver",destination_metadata['engine'],re.IGNORECASE):
                    port = 1433
                else:
                    print("I do not know the default port for rds type: {}".format(destination_metadata['engine']))
                    proceed = False
    #
    # Check instance health for source and destination
    if proceed:
        source_health = check_health(source_metadata['instance_type'],source_metadata['status'])
        if not source_health['healthy']:
            print("Source instance {} is unavailable with a status of '{}'".format(source_name,source_health['status']))
            proceed = False
        else:
            print("Source instance {} is available with a status of '{}'".format(source_name,source_health['status']))
        destination_health = check_health(destination_metadata['instance_type'],destination_metadata['status'])
        if not destination_health['healthy']:
            print("Destination instance {} is unavailable with a status of '{}'".format(destination_name,destination_health['status']))
            proceed = False
        else:
            print("Destination instance {} is available with a status of '{}'".format(destination_name,destination_health['status']))
    #
    # Check if source and destination are both in the same VPC
    if proceed:
        if source_metadata['vpc_id'] != destination_metadata['vpc_id']:
            print("I'm sorry, {} and {} are not in the same VPC. I can only troubleshoot instance connections when they occur in the same VPC.".format(source_name,destination_name))
            proceed = False
        else:
            print("{} and {} are in the same VPC ({})".format(source_name,destination_name,source_metadata['vpc_id']))
    #
    # Check if source and destination are both in the same Subnet
    if proceed:
        if source_metadata['subnet_id'] == destination_metadata['subnet_id']:
            print("{} and {} are in the same subnet ({}). No need to check ACLs".format(source_name,destination_name,source_metadata['subnet_id']))
        else:
            #
            # Check Network ACL Rules
            print("{} is in subnet {}, {} is in subnet {}. Need to check ACLs".format(source_name,source_metadata['subnet_id'],destination_name,destination_metadata['subnet_id']))
            acl_traffic_allowed = check_network_acls(source_metadata['subnet_id'],source_metadata['ip_address'],destination_metadata['subnet_id'],destination_metadata['ip_address'],port,source_metadata['vpc_id'],source_metadata['platform'],ip_protocol)
            if acl_traffic_allowed:
                print("Traffic is allowed through network ACLs on {} port {} between {} and {}".format(ip_protocol.upper(),port,source_name,destination_name))
        #
        # Check Security Group Rules
        sg_traffic_allowed = check_security_groups(source_metadata['security_group_ids'],source_metadata['ip_address'],destination_metadata['security_group_ids'],destination_metadata['ip_address'],port,ip_protocol)
        if sg_traffic_allowed:
            print("Traffic is allowed through security groups on {} port {} between {} and {}".format(ip_protocol.upper(),port,source_name,destination_name))


def get_ec2_metadata(instance_name):
    try:
        instance_found = False
        client = boto3.client('ec2')
        if instance_name[0:2].lower() == 'i-':
            matching_ec2s = client.describe_instances(InstanceIds=[instance_name.lower()])
        else:
            filters = [{'Name':'tag:Name','Values':[instance_name]}]
            matching_ec2s = client.describe_instances(Filters=filters)
        if len(matching_ec2s['Reservations']) == 1:
            instance_found = True
            instance_type = 'EC2'
            if len(matching_ec2s['Reservations'][0]['Instances']) > 1:
                instance_metadata = {'error_type':'ERROR','error_msg':'Multiple EC2 instances found with instance name {}'.format(instance_name)}
            else:
                instance_metadata = matching_ec2s['Reservations'][0]['Instances'][0]
            return instance_found,instance_type,instance_metadata
        elif len(matching_ec2s['Reservations']) > 1:
            instance_found = True
            instance_type = 'EC2'
            instance_metadata = {'error_type':'ERROR','error_msg':'Multiple EC2 instances found with instance name {}'.format(instance_name)}
            return instance_found,instance_type,instance_metadata
        else:
            instance_metadata = {'error_type':'ERROR','error_msg':'No EC2 instance found with name/id {}'.format(instance_name)}
            return instance_found,'UNKNOWN',instance_metadata
    except:
        return instance_found,'UNKNOWN',{'error_type':sys.exc_info()[0],'error_msg':sys.exc_info()[1]}


def get_rds_metadata(instance_name):
    try:
        instance_found = False
        client = boto3.client('rds')
        matching_rds = client.describe_db_instances(DBInstanceIdentifier=instance_name)
        if len(matching_rds['DBInstances']) == 1:
            instance_found = True
            instance_type = 'RDS'
            instance_metadata = matching_rds['DBInstances'][0]
            return instance_found,instance_type,instance_metadata
        elif len(matching_rds['DBInstances']) > 1:
            instance_found = True
            instance_type = 'RDS'
            instance_metadata = {'error_type':'ERROR','error_msg':'Multiple RDS instances found with name {}'.format(instance_name)}
            return instance_found,instance_type,instance_metadata
        else:
            instance_metadata = {'error_type':'ERROR','error_msg':'Did not find RDS instance with name {}'.format(instance_name)}
            return instance_found,'UNKNOWN',instance_metadata
    except:
        return instance_found,'UNKNOWN',{'error_type':sys.exc_info()[0],'error_msg':sys.exc_info()[1]}


def get_instance_metadata(instance_name,instance_type='UNKNOWN'):
    try:
        if instance_type == 'UNKNOWN':
            instance_found,instance_type,instance_metadata = get_ec2_metadata(instance_name)
            if not instance_found:
                instance_found,instance_type,instance_metadata = get_rds_metadata(instance_name)
                if not instance_found:
                    instance_found = False
                    instance_type = 'UNKNOWN'
                    instance_metadata = {'error_type':'ERROR','error_msg':'Did not find EC2 or RDS instance with name {}'.format(instance_name)}
        elif instance_type == 'EC2':
            instance_found,instance_type,instance_metadata = get_ec2_metadata(instance_name)
        elif instance_type == 'RDS':
            instance_found,instance_type,instance_metadata = get_rds_metadata(instance_name)
        else:
            instance_found = False
            instance_type = 'UNKNOWN'
            instance_metadata = {'error_type':'ERROR','error_msg':'Did not find EC2 or RDS instance with name {}'.format(instance_name)}
        if instance_found and 'error_type' not in instance_metadata:
            metadata = parse_metadata(instance_name,instance_metadata,instance_type)
        else:
            metadata = instance_metadata
        return metadata
    except:
        return {'error_type':sys.exc_info()[0],'error_msg':sys.exc_info()[1]}


def parse_metadata(instance_name,instance_metadata,instance_type):
    try:
        metadata = {'instance_name':instance_name,'instance_type':instance_type}
        if instance_type == 'RDS':
            metadata['engine'] = instance_metadata['Engine']
            metadata['status'] = instance_metadata['DBInstanceStatus']
            metadata['security_group_ids'] = [sg['VpcSecurityGroupId'] for sg in instance_metadata['VpcSecurityGroups']]
            rds_az = instance_metadata['AvailabilityZone']
            for subnet in instance_metadata['DBSubnetGroup']['Subnets']:
                if subnet['SubnetAvailabilityZone']['Name'] == rds_az:
                    metadata['subnet_id'] = subnet['SubnetIdentifier']
                    break
            metadata['vpc_id'] = instance_metadata['DBSubnetGroup']['VpcId']
            metadata['publicly_accessible'] = instance_metadata['PubliclyAccessible']
            metadata['port'] = instance_metadata['Endpoint']['Port']
            ec2 = boto3.resource('ec2')
            subnet = ec2.Subnet(metadata['subnet_id'])
            metadata['ip_address'] = {'type':'cidr','value':subnet.cidr_block}
            metadata['platform'] = 'Unknown'
            return metadata
        elif instance_type == 'EC2':
            metadata['instance_id'] = instance_metadata['InstanceId']
            metadata['status'] = instance_metadata['State']['Code']
            metadata['security_group_ids'] = [sg['GroupId'] for sg in instance_metadata['SecurityGroups']]
            metadata['subnet_id'] = instance_metadata['SubnetId']
            metadata['vpc_id'] = instance_metadata['VpcId']
            metadata['ip_address'] = {'type':'ip','value':instance_metadata['NetworkInterfaces'][0]['PrivateIpAddress']}
            if 'Platform' in instance_metadata:
                metadata['platform'] = instance_metadata['Platform']
            else:
                metadata['platform'] = 'Linux'
            return metadata
        else:
            return {'error_type':'ERROR','error_msg':'Instance type not recognized!'}
    except:
        return {'error_type':sys.exc_info()[0],'error_msg':sys.exc_info()[1]}


def check_health(instance_type,instance_status):
    if instance_type == 'EC2':
        if instance_status == 0:
            return {'healthy':False,'status':'Pending'}
        elif instance_status == 16:
            return {'healthy':True,'status':'Running'}
        elif instance_status == 32:
            return {'healthy':False,'status':'Shutting-Down'}
        elif instance_status == 48:
            return {'healthy':False,'status':'Terminated'}
        elif instance_status == 64:
            return {'healthy':False,'status':'Stopping'}
        elif instance_status == 80:
            return {'healthy':False,'status':'Stopped'}
        else:
            return {'healthy':False,'status':'Unknown'}
    elif instance_type == 'RDS':
        if instance_status.upper() == 'AVAILABLE':
            return {'healthy':True,'status':instance_status}
        else:
            return {'healthy':False,'status':instance_status}
    else:
        return {'healthy':False,'status':'Unknown'}


def check_security_groups(source_security_groups,source_ip,destination_security_groups,destination_ip,port,ip_protocol):
    source_ingress,source_egress = get_inbound_outbound_rules('SG',source_security_groups)
    destination_ingress,destination_egress = get_inbound_outbound_rules('SG',destination_security_groups)
    source_egress_allowed = loop_through_rules(object_type='SG',rule_list=source_egress,port=port,target_ip=destination_ip,target_sgs=destination_security_groups,ip_protocol=ip_protocol)
    destination_ingress_allowed = loop_through_rules(object_type='SG',rule_list=destination_ingress,port=port,target_ip=source_ip,target_sgs=source_security_groups,ip_protocol=ip_protocol)
    if not source_egress_allowed:
        print("Outbound traffic to destination not allowed on source's security group for {} port {}".format(ip_protocol.upper(),port))
    if not destination_ingress_allowed:
        print("Inbound traffic from source not allowed on destination's security group for {} port {}".format(ip_protocol.upper(),port))
    if source_egress_allowed and destination_ingress_allowed:
        return True
    else:
        return False


def check_network_acls(source_subnet_id,source_ip,destination_subnet_id,destination_ip,port,vpc_id,source_platform,ip_protocol):
    source_ephemeral = get_ephemeral_ports(source_platform)
    source_ingress,source_egress = get_inbound_outbound_rules('ACL',source_subnet_id,vpc_id)
    destination_ingress,destination_egress = get_inbound_outbound_rules('ACL',destination_subnet_id,vpc_id)
    source_egress_allowed = loop_through_rules(object_type='ACL',rule_list=source_egress,port=port,target_ip=destination_ip,ip_protocol=ip_protocol)
    destination_ingress_allowed = loop_through_rules(object_type='ACL',rule_list=destination_ingress,port=port,target_ip=source_ip,ip_protocol=ip_protocol)
    destination_egress_allowed = loop_through_rules(object_type='ACL',rule_list=destination_egress,port=port,target_ip=source_ip,ephemeral_ports=source_ephemeral,ip_protocol=ip_protocol)
    source_ingress_allowed = loop_through_rules(object_type='ACL',rule_list=source_ingress,port=port,target_ip=destination_ip,ephemeral_ports=source_ephemeral,ip_protocol=ip_protocol)
    if not source_egress_allowed:
        print("Outbound traffic to destination not allowed on source's ACL for {} port {}".format(ip_protocol.upper(),port))
    if not destination_ingress_allowed:
        print("Inbound traffic from source not allowed on destination's ACL for {} port {}".format(ip_protocol.upper(),port))
    if not destination_egress_allowed:
        print("Outbound traffic to source not allowed on destination's ACL for {} ephemeral ports".format(ip_protocol.upper()))
    if not source_ingress_allowed:
        print("Inbound traffic from destination not allowed on source's ACL for {} ephemeral ports".format(ip_protocol.upper()))
    if source_egress_allowed and source_ingress_allowed and destination_egress_allowed and destination_ingress_allowed:
        return True
    else:
        return False


def get_inbound_outbound_rules(object_type,object_ids,vpc_id=None):
    ec2 = boto3.resource('ec2')
    inbound_rules = []
    outbound_rules = []
    if object_type == 'SG':
        for sg_id in object_ids:
            sg = ec2.SecurityGroup(sg_id)
            for inbound_rule in sg.ip_permissions:
                metadata = {}
                if inbound_rule['IpProtocol'] == '-1':
                    metadata['port_range'] = {'from':0,'to':65535}
                    metadata['ip_protocol'] = 'all'
                else:
                    metadata['port_range'] = {'from':inbound_rule['FromPort'],'to':inbound_rule['ToPort']}
                    metadata['ip_protocol'] = inbound_rule['IpProtocol']
                metadata['grantees'] = []
                if len(inbound_rule['IpRanges']) > 0:
                    for grantee in inbound_rule['IpRanges']:
                        metadata['grantees'].append({'type':'cidr','value':grantee['CidrIp']})
                elif len(inbound_rule['UserIdGroupPairs']) > 0:
                    for grantee in inbound_rule['UserIdGroupPairs']:
                        metadata['grantees'].append({'type':'sg','value':grantee['GroupId']})
                inbound_rules.append(metadata)
            for outbound_rule in sg.ip_permissions_egress:
                metadata = {}
                if outbound_rule['IpProtocol'] == '-1':
                    metadata['port_range'] = {'from':0,'to':65535}
                    metadata['ip_protocol'] = 'all'
                else:
                    metadata['port_range'] = {'from':outbound_rule['FromPort'],'to':outbound_rule['ToPort']}
                    metadata['ip_protocol'] = outbound_rule['IpProtocol']
                metadata['grantees'] = []
                if len(outbound_rule['IpRanges']) > 0:
                    for grantee in outbound_rule['IpRanges']:
                        metadata['grantees'].append({'type':'cidr','value':grantee['CidrIp']})
                elif len(outbound_rule['UserIdGroupPairs']) > 0:
                    for grantee in outbound_rule['UserIdGroupPairs']:
                        metadata['grantees'].append({'type':'sg','value':grantee['GroupId']})
                outbound_rules.append(metadata)
    elif object_type == 'ACL':
        client = boto3.client('ec2')
        all_acls = client.describe_network_acls(DryRun=False)
        for acl in all_acls['NetworkAcls']:
            if acl['VpcId'] == vpc_id:
                for association in acl['Associations']:
                    if association['SubnetId'] == object_ids:
                        for entry in acl['Entries']:
                            metadata = {'rule_number':entry['RuleNumber']}
                            if entry['Protocol'] == '-1':
                                metadata['ip_protocol'] = 'all'
                                metadata['port_range'] = {'from':0,'to':65535}
                            else:
                                if entry['Protocol'] == '1':
                                    metadata['ip_protocol'] = 'icmp'
                                elif entry['Protocol'] == '6':
                                    metadata['ip_protocol'] = 'tcp'
                                elif entry['Protocol'] == '17':
                                    metadata['ip_protocol'] = 'udp'
                                metadata['port_range'] = {'from':entry['PortRange']['From'],'to':entry['PortRange']['To']}
                            if entry['RuleAction'] == 'allow':
                                metadata['allow'] = True
                            else:
                                metadata['allow'] = False
                            metadata['grantees'] = [{'type':'cidr','value':entry['CidrBlock']}]
                            if entry['Egress']:
                                outbound_rules.append(metadata)
                            elif not entry['Egress']:
                                inbound_rules.append(metadata)
                        break
    return inbound_rules,outbound_rules


def loop_through_rules(object_type,rule_list,port,target_ip=None,target_sgs=None,ephemeral_ports=None,ip_protocol='tcp'):
    traffic_allowed = False
    if object_type == 'ACL':
        for rule in sorted(rule_list, key=lambda acl_rule: acl_rule['rule_number']):
            match_found = False
            port_match = False
            if rule['ip_protocol'].lower() not in ['all',ip_protocol.lower()]:
                break
            if ephemeral_ports:
                port_match = rule['port_range']['from'] <= ephemeral_ports['from'] and rule['port_range']['to'] >= ephemeral_ports['to']
            else:
                port_match = rule['port_range']['from'] <= port <= rule['port_range']['to']
            if port_match:
                for grantee in rule['grantees']:
                    if target_ip['type'] == 'ip':
                        if netaddr.IPAddress(target_ip['value']) in netaddr.IPNetwork(grantee['value']):
                            if rule['allow']:
                                traffic_allowed = True
                                match_found = True
                                break
                            else:
                                match_found = True
                                break
                    elif target_ip['type'] == 'cidr':
                        if netaddr.IPNetwork(target_ip['value']) in netaddr.IPNetwork(grantee['value']):
                            if rule['allow']:
                                traffic_allowed = True
                                match_found = True
                                break
                            else:
                                match_found = True
                                break
                if match_found:
                    break
    elif object_type == 'SG':
        for rule in rule_list:
            if rule['ip_protocol'].lower() not in ['all',ip_protocol.lower()]:
                break
            if rule['port_range']['from'] <= port <= rule['port_range']['to']:
                for grantee in rule['grantees']:
                    if grantee['type'] == 'sg':
                        if grantee['value'] in target_sgs:
                            traffic_allowed = True
                            break
                    elif grantee['type'] == 'cidr':
                        if target_ip['type'] == 'ip':
                            if netaddr.IPAddress(target_ip['value']) in netaddr.IPNetwork(grantee['value']):
                                traffic_allowed = True
                                break
                        elif target_ip['type'] == 'cidr':
                            if netaddr.IPNetwork(target_ip['value']) in netaddr.IPNetwork(grantee['value']):
                                traffic_allowed = True
                                break
            if traffic_allowed:
                break
    return traffic_allowed


def get_ephemeral_ports(platform):
    if platform.upper() == 'LINUX':
        ephemeral_ports = {'from':32768,'to':61000}
    elif platform.upper() == 'WINDOWS':
        ephemeral_ports = {'from':49152,'to':65535}
    elif platform.upper() == 'UNKNOWN':
        ephemeral_ports = {'from':1024,'to':65535}
    else:
        ephemeral_ports = {'from':1024,'to':65535}
    return ephemeral_ports


if __name__ == '__main__':
    troubleshoot(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5])