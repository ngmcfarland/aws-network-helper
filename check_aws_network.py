import netaddr
import boto3
import json
import sys


def get_metadata(instance_name,instance_type):
    try:
        metadata = {'instance_name':instance_name,'instance_type':instance_type}
        if instance_type == 'RDS':
            client = boto3.client('rds')
            ec2 = boto3.resource('ec2')
            rds_metadata = client.describe_db_instances(DBInstanceIdentifier=instance_name)
            if len(rds_metadata['DBInstances']) == 0:
                metadata = {'error_type':'ERROR','error_msg':'No RDS instances found with instance name {}'.format(instance_name)}
            elif len(rds_metadata['DBInstances']) > 1:
                metadata = {'error_type':'ERROR','error_msg':'Multiple RDS instances found with instance name {}'.format(instance_name)}
            else:
                rds_metadata = rds_metadata['DBInstances'][0]
                metadata['engine'] = rds_metadata['Engine']
                metadata['status'] = rds_metadata['DBInstanceStatus']
                metadata['security_group_ids'] = [sg['VpcSecurityGroupId'] for sg in rds_metadata['VpcSecurityGroups']]
                rds_az = rds_metadata['AvailabilityZone']
                for subnet in rds_metadata['DBSubnetGroup']['Subnets']:
                    if subnet['SubnetAvailabilityZone']['Name'] == rds_az:
                        metadata['subnet_id'] = subnet['SubnetIdentifier']
                        break
                metadata['vpc_id'] = rds_metadata['DBSubnetGroup']['VpcId']
                metadata['publicly_accessible'] = rds_metadata['PubliclyAccessible']
                metadata['port'] = rds_metadata['Endpoint']['Port']
                subnet = ec2.Subnet(metadata['subnet_id'])
                metadata['ip_address'] = {'type':'cidr','value':subnet.cidr_block}
                metadata['platform'] = 'Unknown'
            return metadata
        elif instance_type == 'EC2':
            client = boto3.client('ec2')
            filters = [{'Name':'tag:Name','Values':[instance_name]}]
            ec2_metadata = client.describe_instances(DryRun=False,Filters=filters)
            if len(ec2_metadata['Reservations']) == 0:
                metadata = {'error_type':'ERROR','error_msg':'No EC2 instances found with instance name {}'.format(instance_name)}
            elif len(ec2_metadata['Reservations']) > 1:
                metadata = {'error_type':'ERROR','error_msg':'Multiple EC2 instances found with instance name {}'.format(instance_name)}
            else:
                ec2_metadata = ec2_metadata['Reservations'][0]['Instances'][0]
                metadata['instance_id'] = ec2_metadata['InstanceId']
                metadata['status'] = ec2_metadata['State']['Code']
                metadata['security_group_ids'] = [sg['GroupId'] for sg in ec2_metadata['SecurityGroups']]
                metadata['subnet_id'] = ec2_metadata['SubnetId']
                metadata['vpc_id'] = ec2_metadata['VpcId']
                metadata['ip_address'] = {'type':'ip','value':ec2_metadata['NetworkInterfaces'][0]['PrivateIpAddress']}
                if 'Platform' in ec2_metadata:
                    metadata['platform'] = ec2_metadata['Platform']
                else:
                    metadata['platform'] = 'Linux'
            return metadata
        else:
            return {'error_type':'ERROR','error_msg':'Instance type not recognized!'}
    except:
        return {'error_type':sys.exc_info()[0],'error_msg':sys.exc_info()[1]}


def troubleshoot(source_name,source_type,destination_name,destination_type,port):
    source_metadata = get_metadata(source_name,source_type)
    if 'error_type' in source_metadata:
        print("Uh oh, something went wrong getting metadata for {}!\n{}\n{}".format(source_name,source_metadata['error_type'],source_metadata['error_msg']))
    else:
        print("\nMetadata for {}\n{}\n".format(source_name,source_metadata))
    destination_metadata = get_metadata(destination_name,destination_type)
    if 'error_type' in destination_metadata:
        print("Uh oh, something went wrong getting metadata for {}!\n{}\n{}".format(destination_name,destination_metadata['error_type'],destination_metadata['error_msg']))
    else:
        print("\nMetadata for {}\n{}\n".format(destination_name,destination_metadata))
    #
    # Check instance health for source and destination
    source_health = check_health(source_metadata['instance_type'],source_metadata['status'])
    if not source_health['healthy']:
        print("Source instance {} is unavailable with a status of '{}'".format(source_name,source_health['status']))
    else:
        print("Source instance {} is available with a status of '{}'".format(source_name,source_health['status']))
    destination_health = check_health(destination_metadata['instance_type'],destination_metadata['status'])
    if not destination_health['healthy']:
        print("Destination instance {} is unavailable with a status of '{}'".format(destination_name,destination_health['status']))
    else:
        print("Destination instance {} is available with a status of '{}'".format(destination_name,destination_health['status']))
    #
    # Check if source and destination are both in the same VPC
    if source_metadata['vpc_id'] != destination_metadata['vpc_id']:
        print("I'm sorry, {} and {} are not in the same VPC. I can only troubleshoot instance connections when they occur in the same VPC.".format(source_name,destination_name))
    else:
        print("{} and {} are in the same VPC ({})".format(source_name,destination_name,source_metadata['vpc_id']))
    #
    # Check if source and destination are both in the same Subnet
    if source_metadata['subnet_id'] == destination_metadata['subnet_id']:
        print("{} and {} are in the same subnet ({}). No need to check ACLs".format(source_name,destination_name,source_metadata['subnet_id']))
    else:
        #
        # Check Network ACL Rules
        print("{} is in subnet {}, {} is in subnet {}. Need to check ACLs".format(source_name,source_metadata['subnet_id'],destination_name,destination_metadata['subnet_id']))
        acl_traffic_allowed = check_network_acls(source_metadata['subnet_id'],source_metadata['ip_address'],destination_metadata['subnet_id'],destination_metadata['ip_address'],port,source_metadata['vpc_id'],source_metadata['platform'])
        if acl_traffic_allowed:
            print("Traffic is allowed through network ACLs on port {} between {} and {}".format(port,source_name,destination_name))
    #
    # Check Security Group Rules
    sg_traffic_allowed = check_security_groups(source_metadata['security_group_ids'],source_metadata['ip_address'],destination_metadata['security_group_ids'],destination_metadata['ip_address'],port)
    if sg_traffic_allowed:
        print("Traffic is allowed through security groups on port {} between {} and {}".format(port,source_name,destination_name))
    


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


def check_security_groups(source_security_groups,source_ip,destination_security_groups,destination_ip,port):
    source_ingress,source_egress = get_inbound_outbound_rules('SG',source_security_groups)
    destination_ingress,destination_egress = get_inbound_outbound_rules('SG',destination_security_groups)
    source_egress_allowed = loop_through_rules(object_type='SG',rule_list=source_egress,port=port,target_ip=destination_ip,target_sgs=destination_security_groups)
    destination_ingress_allowed = loop_through_rules(object_type='SG',rule_list=destination_ingress,port=port,target_ip=source_ip,target_sgs=source_security_groups)
    if not source_egress_allowed:
        print("Outbound traffic to destination not allowed on source's security group for port {}".format(port))
    if not destination_ingress_allowed:
        print("Inbound traffic from source not allowed on destination's security group for port {}".format(port))
    if source_egress_allowed and destination_ingress_allowed:
        return True
    else:
        return False


def check_network_acls(source_subnet_id,source_ip,destination_subnet_id,destination_ip,port,vpc_id,source_platform):
    source_ephemeral = get_ephemeral_ports(source_platform)
    source_ingress,source_egress = get_inbound_outbound_rules('ACL',source_subnet_id,vpc_id)
    destination_ingress,destination_egress = get_inbound_outbound_rules('ACL',destination_subnet_id,vpc_id)
    source_egress_allowed = loop_through_rules(object_type='ACL',rule_list=source_egress,port=port,target_ip=destination_ip)
    destination_ingress_allowed = loop_through_rules(object_type='ACL',rule_list=destination_ingress,port=port,target_ip=source_ip)
    destination_egress_allowed = loop_through_rules(object_type='ACL',rule_list=destination_egress,port=port,target_ip=source_ip,ephemeral_ports=source_ephemeral)
    source_ingress_allowed = loop_through_rules(object_type='ACL',rule_list=source_ingress,port=port,target_ip=destination_ip,ephemeral_ports=source_ephemeral)
    if not source_egress_allowed:
        print("Outbound traffic to destination not allowed on source's ACL for port {}".format(port))
    if not destination_ingress_allowed:
        print("Inbound traffic from source not allowed on destination's ACL for port {}".format(port))
    if not destination_egress_allowed:
        print("Outbound traffic to source not allowed on destination's ACL for ephemeral ports")
    if not source_ingress_allowed:
        print("Inbound traffic from destination not allowed on source's ACL for ephemeral ports")
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
                                metadata['ip_protocol'] = entry['Protocol']
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


def loop_through_rules(object_type,rule_list,port,target_ip=None,target_sgs=None,ephemeral_ports=None):
    traffic_allowed = False
    if object_type == 'ACL':
        for rule in sorted(rule_list, key=lambda acl_rule: acl_rule['rule_number']):
            match_found = False
            port_match = False
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