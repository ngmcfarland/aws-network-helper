from conf import check_aws_network_config as config
from datetime import datetime
import netaddr
import logging
import boto3
import json
import sys
import re


logfile = config.logging_file
logging_level = config.logging_level
numeric_level = getattr(logging, logging_level.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: {}'.format(logging_level))

logging.basicConfig(filename=logfile, filemode='w', format='%(asctime)s | %(levelname)-8s | %(funcName)-15s | %(message)s', datefmt='%H:%M:%S', level=numeric_level)


def troubleshoot(source_name,destination_name,port=None,source_type='UNKNOWN',destination_type='UNKNOWN',ip_protocol='tcp'):
    proceed = True
    response = []
    looks_good = []
    needs_work = []
    recommendations = []
    error_messages = []
    #
    # Get metadata for source and destination instances
    logging.info("Starting metadata gathering for {} and {}".format(source_name,destination_name))
    source_metadata = get_instance_metadata(source_name,source_type)
    if 'error_type' in source_metadata:
        logging.error("Error in obtaining metadata for {}:".format(source_name))
        logging.error("{}: {}".format(source_metadata['error_type'],source_metadata['error_msg']))
        error_messages.append("I am not able to retrieve metadata for \"{}\" because {}".format(source_name,source_metadata['error_msg']))
        proceed = False
    else:
        logging.info("Obtained metadata for {} successfully".format(source_name))
        logging.info("Instance type for {}: {}".format(source_name,source_metadata['instance_type']))
    destination_metadata = get_instance_metadata(destination_name,destination_type)
    if 'error_type' in destination_metadata:
        logging.error("Error in obtaining metadata for {}:".format(destination_name))
        logging.error("{}: {}".format(destination_metadata['error_type'],destination_metadata['error_msg']))
        error_messages.append("I am not able to retrieve metadata for \"{}\" because {}".format(destination_name,destination_metadata['error_msg']))
        proceed = False
    else:
        logging.info("Obtained metadata for {} successfully".format(destination_name))
        logging.info("Instance type for {}: {}".format(destination_name,destination_metadata['instance_type']))
    #
    # Check if source and destination are both in the same VPC
    if proceed and source_metadata['instance_type'] not in ['WEB','AWS'] and destination_metadata['instance_type'] not in ['WEB','AWS']:
        logging.info("Checking if {} and {} are in the same AWS VPC".format(source_name,destination_name))
        if source_metadata['vpc_id'] != destination_metadata['vpc_id']:
            logging.error("{} and {} are not in the same VPC. Cross VPC connections are not supported by this script".format(source_name,destination_name))
            error_messages.append("{} and {} are not in the same VPC. I can only troubleshoot connections for instances in the same VPC.".format(source_name,destination_name))
            proceed = False
        else:
            logging.info("{} and {} are in the same VPC ({})".format(source_name,destination_name,source_metadata['vpc_id']))
    #
    # Use default ports if no port passed in
    if proceed:
        if not port:
            logging.info("No port provided. Determining default connection port based on destination")
            if destination_metadata['instance_type'] == 'EC2':
                if destination_metadata['platform'].lower() == 'linux':
                    port = 22
                elif destination_metadata['platform'].lower() == 'windows':
                    port = 3389
                else:
                    logging.error("No default port known for EC2 platform {}".format(destination_metadata['platform']))
                    error_messages.append("I don't know of a default port for EC2 platform: \"{}\"".format(destination_metadata['platform']))
                    proceed = False
            elif destination_metadata['instance_type'] == 'RDS':
                if 'port' in destination_metadata:
                    port = destination_metadata['port']
                else:
                    if re.search(r"oracle",destination_metadata['engine'],re.IGNORECASE):
                        port = 1521
                    elif re.search(r"(mysql|aurora|mariadb)",destination_metadata['engine'],re.IGNORECASE):
                        port = 3306
                    elif re.search(r"postgres",destination_metadata['engine'],re.IGNORECASE):
                        port = 5432
                    elif re.search(r"sqlserver",destination_metadata['engine'],re.IGNORECASE):
                        port = 1433
                    else:
                        logging.error("No default port known for RDS engine {}".format(destination_metadata['engine']))
                        error_messages.append("I don't know of a default port for RDS engine: \"{}\"".format(destination_metadata['engine']))
                        proceed = False
            elif destination_metadata['instance_type'] == 'WEB':
                port = 'WEB'
            elif destination_metadata['instance_type'] == 'AWS':
                port = 443
        if port:
            logging.info("Using port {} for evaluation".format(port))
    #
    # Check instance health for source and destination
    if proceed:
        logging.info("Checking instance health for {} and {}".format(source_name,destination_name))
        source_health = check_health(source_metadata['instance_type'],source_metadata['status'])
        destination_health = check_health(destination_metadata['instance_type'],destination_metadata['status'])
        if source_health['healthy'] and destination_health['healthy']:
            looks_good.append('instance health checks')
            logging.info("Source instance {} is available with a status of '{}'".format(source_name,source_health['status']))
            logging.info("Destination instance {} is available with a status of '{}'".format(destination_name,destination_health['status']))
        else:
            needs_work.append('instance health')
            if not source_health['healthy']:
                logging.info("Source instance {} is unavailable with a status of '{}'".format(source_name,source_health['status']))
                recommendations.append("Check health of {}. Current status: {}".format(source_name,source_health['status']))
            if not destination_health['healthy']:
                logging.info("Destination instance {} is unavailable with a status of '{}'".format(destination_name,destination_health['status']))
                recommendations.append("Check health of {}. Current status: {}".format(destination_name,destination_health['status']))
    #
    # Check what type of traffic to analyze
    if proceed:
        if source_metadata['instance_type'] not in ['WEB','AWS'] and destination_metadata['instance_type'] not in ['WEB','AWS']:
            # Check if source and destination are both in the same Subnet
            logging.info("Checking if {} and {} are in the same VPC subnet".format(source_name,destination_name))
            if source_metadata['subnet_id'] == destination_metadata['subnet_id']:
                logging.info("{} and {} are in the same subnet ({}). Network ACLs do not need to be checked".format(source_name,destination_name,source_metadata['subnet_id']))
            else:
                #
                # Check Network ACL Rules
                logging.info("{} and {} are not in the same subnet".format(source_name,destination_name))
                logging.info("Checking network ACLs")
                acl_traffic_allowed,recommendations = check_network_acls(source_metadata,destination_metadata,port,ip_protocol,recommendations)
                if acl_traffic_allowed:
                    logging.info("Traffic is allowed through network ACLs on {} port {} between {} and {}".format(ip_protocol.upper(),port,source_name,destination_name))
                    looks_good.append('network ACLs')
                else:
                    logging.info("Traffic is not allowed through network ACLs on {} port {} between {} and {}. Recommending:".format(ip_protocol.upper(),port,source_name,destination_name))
                    needs_work.append('network ACLs')
                    for recommendation in recommendations:
                        logging.info(" - {}".format(recommendation))
            #
            # Check Security Group Rules
            sg_traffic_allowed,recommendations = check_security_groups(source_metadata,destination_metadata,port,ip_protocol,recommendations)
            if sg_traffic_allowed:
                logging.info("Traffic is allowed through security groups on {} port {} between {} and {}".format(ip_protocol.upper(),port,source_name,destination_name))
                looks_good.append('security groups')
            else:
                logging.info("Traffic is not allowed through security groups on {} port {} between {} and {} for the following reasons:".format(ip_protocol.upper(),port,source_name,destination_name))
                needs_work.append('security groups')
                for recommendation in recommendations:
                    logging.info(" - {}".format(recommendation))
        else:
            # Troubleshoot web traffic
            if source_metadata['instance_type'] in ['WEB','AWS']:
                web_traffic_direction = 'IN'
                logging.info("Direction of web traffic: {}".format(web_traffic_direction))
                logging.info("Getting metadata for network gateway")
                gateway_metadata = get_instance_metadata(destination_metadata['subnet_id'],'GATEWAY')
                if 'error_type' in gateway_metadata:
                    logging.error("Error in obtaining metadata for gateway associated with {}:".format(destination_metadata['subnet_id']))
                    logging.error("{}: {}".format(gateway_metadata['error_type'],gateway_metadata['error_msg']))
                    error_messages.append("I am not able to retrieve metadata for the gateway associated with subnet \"{}\" because {}".format(destination_metadata['subnet_id'],destination_metadata['error_msg']))
                else:
                    recommendations,needs_work,looks_good = check_web_traffic(source_metadata,destination_metadata,gateway_metadata,web_traffic_direction,port,ip_protocol,recommendations,needs_work,looks_good)
            elif destination_metadata['instance_type'] in ['WEB','AWS']:
                web_traffic_direction = 'OUT'
                logging.info("Direction of web traffic: {}".format(web_traffic_direction))
                logging.info("Getting metadata for network gateway")
                gateway_metadata = get_instance_metadata(source_metadata['subnet_id'],'GATEWAY')
                if 'error_type' in gateway_metadata:
                    logging.error("Error in obtaining metadata for gateway associated with {}:".format(destination_metadata['subnet_id']))
                    logging.error("{}: {}".format(gateway_metadata['error_type'],gateway_metadata['error_msg']))
                    error_messages.append("I am not able to retrieve metadata for the gateway associated with subnet \"{}\" because {}".format(destination_metadata['subnet_id'],destination_metadata['error_msg']))
                else:
                    recommendations,needs_work,looks_good = check_web_traffic(source_metadata,destination_metadata,gateway_metadata,web_traffic_direction,port,ip_protocol,recommendations,needs_work,looks_good)
    #
    # Compile results
    if len(error_messages) > 0:
        response.append("I'm sorry, {}. If you can help me troubleshoot these issues, I can try taking a look at your network again.".format(format_list(error_messages)))
    else:
        if len(looks_good) > 0:
            response.append("I've checked your {} and everything there looks good.".format(format_list(looks_good)))
        if len(needs_work) > 0:
            response.append("I have some recommendations about your {}:".format(format_list(needs_work)))
            for recommendation in recommendations:
                response.append(" - {}".format(recommendation))
        else:
            if destination_metadata['instance_type'] != 'UNKNOWN':
                response.append("Based on everything I've looked at, you should be able to connect. If you are still having issues, here are some general things to check:")
                if destination_metadata['instance_type'] == 'EC2':
                    for recommendation in config.general_recommendations['EC2']['recommendations']:
                        response.append(" - {}".format(recommendation))
                elif destination_metadata['instance_type'] == 'RDS':
                    for recommendation in config.general_recommendations['RDS']['recommendations']:
                        response.append(" - {}".format(recommendation))
                elif destination_metadata['instance_type'] == 'AWS':
                    for recommendation in config.general_recommendations['AWS']['recommendations']:
                        response.append(" - {}".format(recommendation))
                elif destination_metadata['instance_type'] == 'WEB':
                    for recommendation in config.general_recommendations['WEB']['recommendations']:
                        response.append(" - {}".format(recommendation))
            else:
                response.append("Based on everything I've looked at, you should be able to connect.")
        if destination_metadata['instance_type'] == 'EC2':
            response.append("Additional Documentation: {}".format(config.general_recommendations['EC2']['url']))
        elif destination_metadata['instance_type'] == 'RDS':
            response.append("Additional Documentation: {}".format(config.general_recommendations['RDS']['url']))
        elif destination_metadata['instance_type'] == 'AWS':
            response.append("Additional Documentation: {}".format(config.general_recommendations['AWS']['url']))
        else:
            if source_metadata['instance_type'] == 'EC2':
                response.append("Additional Documentation: {}".format(config.general_recommendations['EC2']['url']))
            elif source_metadata['instance_type'] == 'RDS':
                response.append("Additional Documentation: {}".format(config.general_recommendations['RDS']['url']))
            elif source_metadata['instance_type'] == 'AWS':
                response.append("Additional Documentation: {}".format(config.general_recommendations['AWS']['url']))
    return "\n".join(response)



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
                instance_metadata = {'error_type':'ERROR','error_msg':'I found multiple EC2 instances with the name "{}"'.format(instance_name)}
            else:
                instance_metadata = matching_ec2s['Reservations'][0]['Instances'][0]
            return instance_found,instance_type,instance_metadata
        elif len(matching_ec2s['Reservations']) > 1:
            instance_found = True
            instance_type = 'EC2'
            instance_metadata = {'error_type':'ERROR','error_msg':'I found multiple EC2 instances with the name "{}"'.format(instance_name)}
            return instance_found,instance_type,instance_metadata
        else:
            instance_metadata = {'error_type':'ERROR','error_msg':'I didn\'t find any EC2 instances with the name/id: "{}"'.format(instance_name)}
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
            instance_metadata = {'error_type':'ERROR','error_msg':'I found multiple RDS instances with the name "{}"'.format(instance_name)}
            return instance_found,instance_type,instance_metadata
        else:
            instance_metadata = {'error_type':'ERROR','error_msg':'I did not find an RDS instance with the name "{}"'.format(instance_name)}
            return instance_found,'UNKNOWN',instance_metadata
    except:
        return instance_found,'UNKNOWN',{'error_type':sys.exc_info()[0],'error_msg':sys.exc_info()[1]}


def get_gateway_metadata(subnet_id):
    gateway_metadata = None
    gateway_found = False
    client = boto3.client('ec2')
    route_table = client.describe_route_tables(Filters=[{'Name':'association.subnet-id','Values':[subnet_id]}])
    if len(route_table['RouteTables']) == 1:
        for route in route_table['RouteTables'][0]['Routes']:
            if route['State'] == 'active':
                if 'GatewayId' in route:
                    if route['GatewayId'] != 'local':
                        gateway_metadata = {'id':route['GatewayId'],'type':'IGW','target':route['DestinationCidrBlock']}
                        gateway_found = True
                        break
                else:
                    if 'NatGatewayId' in route:
                        nat_gateway = client.describe_nat_gateways(NatGatewayIds=[route['NatGatewayId']])
                        nat_subnet = client.describe_subnets(SubnetIds=[nat_gateway['NatGateways'][0]['SubnetId']])
                        gateway_metadata = {'id':route['NatGatewayId'],'type':'NAT','target':route['DestinationCidrBlock'],'subnet':nat_gateway['NatGateways'][0]['SubnetId'],'subnet_cidr':{'type':'cidr','value':nat_subnet['Subnets'][0]['CidrBlock']}}
                        gateway_found = True
                        break
        if not gateway_metadata:
            gateway_metadata = {'error_type':'GATEWAY_NOT_FOUND','error_msg':'I could not identify a gateway in the route table "{}"'.format(route_table['RouteTables'][0]['RouteTableId'])}
    elif len(route_table['RouteTables']) == 0:
        gateway_metadata = {'error_type':'NO_ROUTE_TABLE','error_msg':'I could not find a route table for subnet "{}"'.format(subnet_id)}
    else:
        gateway_metadata = {'error_type':'MULTIPLE_ROUTE_TABLES','error_msg':'I found multiple route tables for subnet "{}"'.format(subnet_id)}
    return gateway_found,'GATEWAY',gateway_metadata


def get_instance_metadata(instance_name,instance_type='UNKNOWN'):
    try:
        if instance_type == 'UNKNOWN':
            if instance_name.upper() in ['INTERNET','WEB','THE INTERNET','THE WEB','MY COMPUTER']:
                instance_found = True
                instance_type = 'WEB'
                instance_metadata = {}
            elif instance_name.upper() in ['S3','KMS','SNS','SQS','DYNAMO','DYNAMODB']:
                instance_found = True
                instance_type = 'AWS'
                instance_metadata = {}
            else:
                instance_found,instance_type,instance_metadata = get_ec2_metadata(instance_name)
                if not instance_found:
                    instance_found,instance_type,instance_metadata = get_rds_metadata(instance_name)
                    if not instance_found:
                        instance_found = False
                        instance_type = 'UNKNOWN'
                        instance_metadata = {'error_type':'INSTANCE_MATCH_ERROR','error_msg':'I did not find an EC2 or RDS instance with the name "{}"'.format(instance_name)}
        elif instance_type == 'EC2':
            instance_found,instance_type,instance_metadata = get_ec2_metadata(instance_name)
        elif instance_type == 'RDS':
            instance_found,instance_type,instance_metadata = get_rds_metadata(instance_name)
        elif instance_type == 'GATEWAY':
            instance_found,instance_type,instance_metadata = get_gateway_metadata(instance_name)
        else:
            instance_found = False
            instance_type = 'UNKNOWN'
            instance_metadata = {'error_type':'UNKOWN_INSTANCE_TYPE_ERROR','error_msg':'an unknown instance type was provided: "{}"'.format(instance_type)}
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
            if 'PublicIpAddress' in instance_metadata:
                metadata['public_ip'] = instance_metadata['PublicIpAddress']
            if 'Platform' in instance_metadata:
                metadata['platform'] = instance_metadata['Platform']
            else:
                metadata['platform'] = 'Linux'
            return metadata
        elif instance_type in ['WEB','AWS']:
            metadata['status'] = 'N/A'
            return metadata
        elif instance_type == 'GATEWAY':
            return instance_metadata
        else:
            return {'error_type':'ERROR','error_msg':'the instance type was not recognized'}
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
    elif instance_type in ['WEB','AWS']:
        return {'healthy':True,'status':'N/A'}
    else:
        return {'healthy':False,'status':'Unknown'}


def check_security_groups(source_metadata,destination_metadata,port,ip_protocol,recommendations):
    source_sg_names,source_ingress,source_egress = get_inbound_outbound_rules('SG',source_metadata['security_group_ids'])
    destination_sg_names,destination_ingress,destination_egress = get_inbound_outbound_rules('SG',destination_metadata['security_group_ids'])
    source_egress_allowed = loop_through_rules(object_type='SG',rule_list=source_egress,port=port,target_ip=destination_metadata['ip_address'],target_sgs=destination_metadata['security_group_ids'],ip_protocol=ip_protocol)
    destination_ingress_allowed = loop_through_rules(object_type='SG',rule_list=destination_ingress,port=port,target_ip=source_metadata['ip_address'],target_sgs=source_metadata['security_group_ids'],ip_protocol=ip_protocol)
    if not source_egress_allowed:
        recommendations.append("Allow outbound traffic to {} on one of {}'s security groups ({}) for {} port {}".format(destination_metadata['ip_address']['value'],source_metadata['instance_name'],format_list(source_sg_names,'or'),ip_protocol.upper(),port))
    if not destination_ingress_allowed:
        recommendations.append("Allow inbound traffic from {} on one of {}'s security groups ({}) for {} port {}".format(source_metadata['ip_address']['value'],destination_metadata['instance_name'],format_list(destination_sg_names,'or'),ip_protocol.upper(),port))
    if source_egress_allowed and destination_ingress_allowed:
        return True,recommendations
    else:
        return False,recommendations


def check_network_acls(source_metadata,destination_metadata,port,ip_protocol,recommendations):
    source_ephemeral = get_ephemeral_ports(source_metadata['platform'])
    source_acl_names,source_ingress,source_egress = get_inbound_outbound_rules('ACL',source_metadata['subnet_id'])
    destination_acl_names,destination_ingress,destination_egress = get_inbound_outbound_rules('ACL',destination_metadata['subnet_id'])
    source_egress_allowed = loop_through_rules(object_type='ACL',rule_list=source_egress,port=port,target_ip=destination_metadata['ip_address'],ip_protocol=ip_protocol)
    destination_ingress_allowed = loop_through_rules(object_type='ACL',rule_list=destination_ingress,port=port,target_ip=source_metadata['ip_address'],ip_protocol=ip_protocol)
    destination_egress_allowed = loop_through_rules(object_type='ACL',rule_list=destination_egress,port=port,target_ip=source_metadata['ip_address'],ephemeral_ports=source_ephemeral,ip_protocol=ip_protocol)
    source_ingress_allowed = loop_through_rules(object_type='ACL',rule_list=source_ingress,port=port,target_ip=destination_metadata['ip_address'],ephemeral_ports=source_ephemeral,ip_protocol=ip_protocol)
    if not source_egress_allowed:
        recommendations.append("Allow outbound traffic to {} on {}'s ACL ({}) for {} port {}".format(destination_metadata['ip_address']['value'],source_metadata['instance_name'],source_acl_names[0],ip_protocol.upper(),port))
    if not destination_ingress_allowed:
        recommendations.append("Allow inbound traffic from {} on {}'s ACL ({}) for {} port {}".format(source_metadata['ip_address']['value'],destination_metadata['instance_name'],destination_acl_names[0],ip_protocol.upper(),port))
    if not destination_egress_allowed:
        recommendations.append("Allow outbound traffic to {} on {}'s ACL ({}) for {} ephemeral port range: {}-{}".format(source_metadata['ip_address']['value'],destination_metadata['instance_name'],destination_acl_names[0],ip_protocol.upper(),source_ephemeral['from'],source_ephemeral['to']))
    if not source_ingress_allowed:
        recommendations.append("Allow inbound traffic from {} on {}'s ACL ({}) for {} ephemeral port range: {}-{}".format(destination_metadata['ip_address']['value'],source_metadata['instance_name'],source_acl_names[0],ip_protocol.upper(),source_ephemeral['from'],source_ephemeral['to']))
    if source_egress_allowed and source_ingress_allowed and destination_egress_allowed and destination_ingress_allowed:
        return True,recommendations
    else:
        return False,recommendations


def check_web_traffic(source_metadata,destination_metadata,gateway_metadata,web_traffic_direction,port,ip_protocol,recommendations,needs_work,looks_good):
    logging.info("Gateway is of type: {}".format(gateway_metadata['type']))
    if web_traffic_direction == 'IN':
        if gateway_metadata['type'] == 'NAT':
            logging.info("Gateway is of type: {}".format(gateway_metadata['type']))
            needs_work.append('route tables')
            recommendations.append("Your instance is behind a NAT gateway, and is not publicly accessible from the internet. Move your instance to a public route table, or connect to it from a server that is within your VPC.")
            logging.info("User is trying to connect to instance through NAT gateway")
        elif gateway_metadata['type'] == 'IGW':
            logging.info("Gateway is of type: {}".format(gateway_metadata['type']))
            if destination_metadata['instance_type'] == 'EC2':
                if 'public_ip' not in destination_metadata:
                    needs_work.append('EC2 instance')
                    recommendations.append("Your EC2 instance does not have a public IP address which is required for inbound traffic through your internet gateway.")
                    logging.info("Target instance does not have a public IP address")
                else:
                    logging.info("Target instance has public IP address")
            elif destination_metadata['instance_type'] == 'RDS':
                if not destination_metadata['publicly_accessible']:
                    needs_work.append('RDS instance')
                    recommendations.append("Your RDS instance is not publicly accessible. Change the settings on your RDS instance or connect from an EC2 instance inside your VPC.")
                    logging.info("Target RDS is not set to be publicly accessible")
                else:
                    logging.info("Target RDS is publicly accessible")
            logging.info("Now checking to see if traffic is allowed through ACLs on port {}".format(port))
            acl_traffic_allowed,recommendations = check_network_acls_for_web(source_metadata,destination_metadata,web_traffic_direction,gateway_metadata,port,ip_protocol,recommendations)
            if acl_traffic_allowed:
                logging.info("Web traffic is allowed through network ACLs on {} port {} between {} and {}".format(ip_protocol.upper(),port,source_metadata['instance_name'],destination_metadata['instance_name']))
                looks_good.append('network ACLs')
            else:
                logging.info("Web traffic is not allowed through network ACLs on {} port {} between {} and {}. Recommending:".format(ip_protocol.upper(),port,source_metadata['instance_name'],destination_metadata['instance_name']))
                needs_work.append('network ACLs')
            for recommendation in recommendations:
                logging.info(" - {}".format(recommendation))
            logging.info("Now checking to see if traffic is allowed through security groups on port {}".format(port))
            sg_traffic_allowed,recommendations = check_security_groups_for_web(source_metadata,destination_metadata,web_traffic_direction,gateway_metadata,port,ip_protocol,recommendations)
            if sg_traffic_allowed:
                logging.info("Web traffic is allowed through security groups on {} port {} between {} and {}".format(ip_protocol.upper(),port,source_metadata['instance_name'],destination_metadata['instance_name']))
                looks_good.append('security groups')
            else:
                logging.info("Web traffic is not allowed through security groups on {} port {} between {} and {} for the following reasons:".format(ip_protocol.upper(),port,source_metadata['instance_name'],destination_metadata['instance_name']))
                needs_work.append('security groups')
                for recommendation in recommendations:
                    logging.info(" - {}".format(recommendation))
    elif web_traffic_direction == 'OUT':
        if source_metadata['instance_type'] == 'EC2':
            if 'public_ip' not in source_metadata:
                needs_work.append('EC2 instance')
                recommendations.append("Your EC2 instance does not have a public IP address which is required for return traffic through your internet gateway.")
                logging.info("Target instance does not have a public IP address")
            else:
                logging.info("Target instance has public IP address")
        elif source_metadata['instance_type'] == 'RDS':
            if not source_metadata['publicly_accessible']:
                needs_work.append('RDS instance')
                recommendations.append("Your RDS instance is not publicly accessible which is required for return traffic through your internet gateway.")
                logging.info("Target RDS is not set to be publicly accessible")
            else:
                logging.info("Target RDS is publicly accessible")
        if port == 'WEB':
            web_ports = [80,443]
            acls_look_good = []
            sgs_look_good = []
            for web_port in web_ports:
                logging.info("Now checking to see if traffic is allowed through ACLs on port {}".format(web_port))
                acl_traffic_allowed,recommendations = check_network_acls_for_web(source_metadata,destination_metadata,web_traffic_direction,gateway_metadata,web_port,ip_protocol,recommendations)
                if acl_traffic_allowed:
                    logging.info("Web traffic is allowed through network ACLs on {} port {} between {} and {}".format(ip_protocol.upper(),web_port,source_metadata['instance_name'],destination_metadata['instance_name']))
                    acls_look_good.append('Y')
                else:
                    logging.info("Web traffic is not allowed through network ACLs on {} port {} between {} and {}. Recommending:".format(ip_protocol.upper(),web_port,source_metadata['instance_name'],destination_metadata['instance_name']))
                    acls_look_good.append('N')
                for recommendation in recommendations:
                    logging.info(" - {}".format(recommendation))
                logging.info("Now checking to see if traffic is allowed through security groups on port {}".format(web_port))
                sg_traffic_allowed,recommendations = check_security_groups_for_web(source_metadata,destination_metadata,web_traffic_direction,gateway_metadata,web_port,ip_protocol,recommendations)
                if sg_traffic_allowed:
                    logging.info("Web traffic is allowed through security groups on {} port {} between {} and {}".format(ip_protocol.upper(),web_port,source_metadata['instance_name'],destination_metadata['instance_name']))
                    sgs_look_good.append('Y')
                else:
                    logging.info("Web traffic is not allowed through security groups on {} port {} between {} and {} for the following reasons:".format(ip_protocol.upper(),web_port,source_metadata['instance_name'],destination_metadata['instance_name']))
                    sgs_look_good.append('N')
                    for recommendation in recommendations:
                        logging.info(" - {}".format(recommendation))
            needs_work.append('network ACLs') if 'N' in acls_look_good else looks_good.append('network ACLs')
            needs_work.append('security groups') if 'N' in sgs_look_good else looks_good.append('security groups')
        else:
            logging.info("Now checking to see if traffic is allowed through ACLs on port {}".format(port))
            acl_traffic_allowed,recommendations = check_network_acls_for_web(source_metadata,destination_metadata,web_traffic_direction,gateway_metadata,port,ip_protocol,recommendations)
            if acl_traffic_allowed:
                logging.info("Web traffic is allowed through network ACLs on {} port {} between {} and {}".format(ip_protocol.upper(),port,source_metadata['instance_name'],destination_metadata['instance_name']))
                looks_good.append('network ACLs')
            else:
                logging.info("Web traffic is not allowed through network ACLs on {} port {} between {} and {}. Recommending:".format(ip_protocol.upper(),port,source_metadata['instance_name'],destination_metadata['instance_name']))
                needs_work.append('network ACLs')
            for recommendation in recommendations:
                logging.info(" - {}".format(recommendation))
            logging.info("Now checking to see if traffic is allowed through security groups on port {}".format(port))
            sg_traffic_allowed,recommendations = check_security_groups_for_web(source_metadata,destination_metadata,web_traffic_direction,gateway_metadata,port,ip_protocol,recommendations)
            if sg_traffic_allowed:
                logging.info("Web traffic is allowed through security groups on {} port {} between {} and {}".format(ip_protocol.upper(),port,source_metadata['instance_name'],destination_metadata['instance_name']))
                looks_good.append('security groups')
            else:
                logging.info("Web traffic is not allowed through security groups on {} port {} between {} and {} for the following reasons:".format(ip_protocol.upper(),port,source_metadata['instance_name'],destination_metadata['instance_name']))
                needs_work.append('security groups')
                for recommendation in recommendations:
                    logging.info(" - {}".format(recommendation))
    return recommendations,needs_work,looks_good


def check_security_groups_for_web(source_metadata,destination_metadata,web_traffic_direction,gateway_metadata,port,ip_protocol,recommendations):
    if gateway_metadata['type'] == 'IGW':
        if web_traffic_direction == 'IN':
            destination_sg_names,destination_ingress,destination_egress = get_inbound_outbound_rules('SG',destination_metadata['security_group_ids'])
            destination_ingress_allowed = loop_through_rules(object_type='SG',rule_list=destination_ingress,port=port,target_ip={'type':'cidr','value':'0.0.0.0/0'},target_sgs=[],ip_protocol=ip_protocol)
            if not destination_ingress_allowed:
                recommendations.append("Allow inbound traffic from 0.0.0.0/0 or your IP on one of {}'s security groups ({}) for {} port {}".format(destination_metadata['instance_name'],format_list(destination_sg_names,'or'),ip_protocol.upper(),port))
                return False,recommendations
            else:
                return True,recommendations
        elif web_traffic_direction == 'OUT':
            source_sg_names,source_ingress,source_egress = get_inbound_outbound_rules('SG',source_metadata['security_group_ids'])
            source_egress_allowed = loop_through_rules(object_type='SG',rule_list=source_egress,port=port,target_ip={'type':'cidr','value':'0.0.0.0/0'},target_sgs=[],ip_protocol=ip_protocol)
            if not source_egress_allowed:
                recommendations.append("Allow outbound traffic to 0.0.0.0/0 on one of {}'s security groups ({}) for {} port {}".format(source_metadata['instance_name'],format_list(source_sg_names,'or'),ip_protocol.upper(),port))
                return False,recommendations
            else:
                return True,recommendations
    elif gateway_metadata['type'] == 'NAT':
        if web_traffic_direction == 'IN':
            recommendations.append("Inbound traffic from the internet not allowed to instances in private route tables.")
            return False,recommendations
        elif web_traffic_direction == 'OUT':
            source_sg_names,source_ingress,source_egress = get_inbound_outbound_rules('SG',source_metadata['security_group_ids'])
            source_egress_allowed = loop_through_rules(object_type='SG',rule_list=source_egress,port=port,target_ip=gateway_metadata['subnet_cidr'],target_sgs=[],ip_protocol=ip_protocol)
            if not source_egress_allowed:
                recommendations.append("Allow outbound traffic to {} on one of {}'s security groups ({}) for {} port {}".format(gateway_metadata['subnet_cidr'],source_metadata['instance_name'],format_list(source_sg_names,'or'),ip_protocol.upper(),port))
                return False,recommendations
            else:
                return True,recommendations


def check_network_acls_for_web(source_metadata,destination_metadata,web_traffic_direction,gateway_metadata,port,ip_protocol,recommendations):
    if gateway_metadata['type'] == 'IGW':
        if web_traffic_direction == 'IN':
            source_ephemeral = get_ephemeral_ports('UNKNOWN')
            destination_acl_names,destination_ingress,destination_egress = get_inbound_outbound_rules('ACL',destination_metadata['subnet_id'])
            destination_ingress_allowed = loop_through_rules(object_type='ACL',rule_list=destination_ingress,port=port,target_ip={'type':'cidr','value':'0.0.0.0/0'},ip_protocol=ip_protocol)
            destination_egress_allowed = loop_through_rules(object_type='ACL',rule_list=destination_egress,port=port,target_ip={'type':'cidr','value':'0.0.0.0/0'},ephemeral_ports=source_ephemeral,ip_protocol=ip_protocol)
            if not destination_ingress_allowed:
                recommendations.append("Allow inbound traffic from 0.0.0.0/0 or your IP on {}'s ACL ({}) for {} port {}".format(destination_metadata['instance_name'],destination_acl_names[0],ip_protocol.upper(),port))
            if not destination_egress_allowed:
                recommendations.append("Allow outbound traffic to 0.0.0.0/0 or your IP on {}'s ACL ({}) for {} ephemeral port range: {}-{}".format(destination_metadata['instance_name'],destination_acl_names[0],ip_protocol.upper(),source_ephemeral['from'],source_ephemeral['to']))
            if destination_ingress_allowed and destination_egress_allowed:
                return True,recommendations
            else:
                return False,recommendations
        elif web_traffic_direction == 'OUT':
            source_ephemeral = get_ephemeral_ports(source_metadata['platform'])
            source_acl_names,source_ingress,source_egress = get_inbound_outbound_rules('ACL',source_metadata['subnet_id'])
            source_egress_allowed = loop_through_rules(object_type='ACL',rule_list=source_egress,port=port,target_ip={'type':'cidr','value':'0.0.0.0/0'},ip_protocol=ip_protocol)
            source_ingress_allowed = loop_through_rules(object_type='ACL',rule_list=source_ingress,port=port,target_ip={'type':'cidr','value':'0.0.0.0/0'},ephemeral_ports=source_ephemeral,ip_protocol=ip_protocol)
            if not source_egress_allowed:
                recommendations.append("Allow outbound traffic to 0.0.0.0/0 on {}'s ACL ({}) for {} port {}".format(source_metadata['instance_name'],source_acl_names[0],ip_protocol.upper(),port))
            if not source_ingress_allowed:
                recommendations.append("Allow inbound traffic from 0.0.0.0/0 on {}'s ACL ({}) for {} ephemeral port range: {}-{}".format(source_metadata['instance_name'],source_acl_names[0],ip_protocol.upper(),source_ephemeral['from'],source_ephemeral['to']))
            if source_egress_allowed and source_ingress_allowed:
                return True,recommendations
            else:
                return False,recommendations
    elif gateway_metadata['type'] == 'NAT':
        if web_traffic_direction == 'IN':
            recommendations.append("Inbound traffic from the internet not allowed to instances in private route tables.")
            return False,recommendations
        elif web_traffic_direction == 'OUT':
            source_ephemeral = get_ephemeral_ports(source_metadata['platform'])
            source_acl_names,source_ingress,source_egress = get_inbound_outbound_rules('ACL',source_metadata['subnet_id'])
            source_egress_allowed = loop_through_rules(object_type='ACL',rule_list=source_egress,port=port,target_ip=gateway_metadata['subnet_cidr'],ip_protocol=ip_protocol)
            source_ingress_allowed = loop_through_rules(object_type='ACL',rule_list=source_ingress,port=port,target_ip=gateway_metadata['subnet_cidr'],ephemeral_ports=source_ephemeral,ip_protocol=ip_protocol)
            nat_acl_names,nat_ingress,nat_egress = get_inbound_outbound_rules('ACL',gateway_metadata['subnet'])
            nat_ingress_allowed = loop_through_rules(object_type='ACL',rule_list=nat_ingress,port=port,target_ip=gateway_metadata['subnet_cidr'],ip_protocol=ip_protocol)
            nat_egress_allowed = loop_through_rules(object_type='ACL',rule_list=nat_egress,port=port,target_ip={'type':'cidr','value':'0.0.0.0/0'},ip_protocol=ip_protocol)
            nat_ingress_ephemeral_allowed = loop_through_rules(object_type='ACL',rule_list=nat_ingress,port=port,target_ip={'type':'cidr','value':'0.0.0.0/0'},ephemeral_ports=source_ephemeral,ip_protocol=ip_protocol)
            nat_egress_ephemeral_allowed = loop_through_rules(object_type='ACL',rule_list=nat_egress,port=port,target_ip=gateway_metadata['subnet_cidr'],ephemeral_ports=source_ephemeral,ip_protocol=ip_protocol)
            if not source_egress_allowed:
                recommendations.append("Allow outbound traffic to {} on {}'s ACL ({}) for {} port {}".format(gateway_metadata['subnet_cidr'],source_metadata['instance_name'],source_acl_names[0],ip_protocol.upper(),port))
            if not source_ingress_allowed:
                recommendations.append("Allow inbound traffic from {} on {}'s ACL ({}) for {} ephemeral port range: {}-{}".format(gateway_metadata['subnet_cidr'],source_metadata['instance_name'],source_acl_names[0],ip_protocol.upper(),source_ephemeral['from'],source_ephemeral['to']))
            if not nat_ingress_allowed:
                recommendations.append("Allow inbound traffic from {} on your NAT gateways ACL ({}) for {} port {}".format(source_metadata['ip_address']['value'],nat_acl_names[0],ip_protocol.upper(),port))
            if not nat_egress_allowed:
                recommendations.append("Allow outbound traffic to 0.0.0.0/0 on your NAT gateways ACL ({}) for {} port {}".format(nat_acl_names[0],ip_protocol.upper(),port))
            if not nat_ingress_ephemeral_allowed:
                recommendations.append("Allow inbound traffic from 0.0.0.0/0 on your NAT gateways ACL ({}) for {} ephemeral port range: {}-{}".format(nat_acl_names[0],ip_protocol.upper(),source_ephemeral['from'],source_ephemeral['to']))
            if not nat_egress_ephemeral_allowed:
                recommendations.append("Allow outbound traffic to {} on your NAT gateways ACL ({}) for {} ephemeral port range: {}-{}".format(source_metadata['ip_address']['value'],nat_acl_names[0],ip_protocol.upper(),source_ephemeral['from'],source_ephemeral['to']))
            if source_egress_allowed and source_ingress_allowed and nat_ingress_allowed and nat_egress_allowed and nat_ingress_ephemeral_allowed and nat_egress_ephemeral_allowed:
                return True,recommendations
            else:
                return False,recommendations


def get_inbound_outbound_rules(object_type,object_ids):
    ec2 = boto3.resource('ec2')
    inbound_rules = []
    outbound_rules = []
    if object_type == 'SG':
        object_names = []
        for sg_id in object_ids:
            sg = ec2.SecurityGroup(sg_id)
            object_names.append(sg.group_name)
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
        subnet_acl = client.describe_network_acls(Filters=[{'Name':'association.subnet-id','Values':[object_ids]}])
        object_names = map(lambda x: x['Value'], filter(lambda y: y['Key'] == 'Name', subnet_acl['NetworkAcls'][0]['Tags']))
        object_names = subnet_acl['NetworkAcls'][0]['NetworkAclId'] if len(object_names) == 0 else object_names
        for entry in subnet_acl['NetworkAcls'][0]['Entries']:
            metadata = {'rule_number':entry['RuleNumber']}
            if entry['Protocol'] == '-1':
                metadata['ip_protocol'] = 'all'
                metadata['port_range'] = {'from':0,'to':65535}
            else:
                if entry['Protocol'] == '1':
                    metadata['ip_protocol'] = 'icmp'
                    # Need to add port range logic
                elif entry['Protocol'] == '6':
                    metadata['ip_protocol'] = 'tcp'
                    metadata['port_range'] = {'from':entry['PortRange']['From'],'to':entry['PortRange']['To']}
                elif entry['Protocol'] == '17':
                    metadata['ip_protocol'] = 'udp'
                    # Need to add port range logic
                # else:
                #       Need to add other protocol logic
            if entry['RuleAction'] == 'allow':
                metadata['allow'] = True
            else:
                metadata['allow'] = False
            metadata['grantees'] = [{'type':'cidr','value':entry['CidrBlock']}]
            if entry['Egress']:
                outbound_rules.append(metadata)
            elif not entry['Egress']:
                inbound_rules.append(metadata)
    return object_names,inbound_rules,outbound_rules


def loop_through_rules(object_type,rule_list,port,target_ip=None,target_sgs=None,ephemeral_ports=None,ip_protocol='tcp'):
    traffic_allowed = False
    if object_type == 'ACL':
        for rule in sorted(rule_list, key=lambda acl_rule: acl_rule['rule_number']):
            match_found = False
            port_match = False
            if rule['ip_protocol'].lower() in ['all',ip_protocol.lower()]:
                if ephemeral_ports:
                    logging.info("Checking if {}-{} in {}-{}".format(ephemeral_ports['from'],ephemeral_ports['to'],rule['port_range']['from'],rule['port_range']['to']))
                    port_match = rule['port_range']['from'] <= ephemeral_ports['from'] and rule['port_range']['to'] >= ephemeral_ports['to']
                    logging.info("port_match = {}".format(port_match))
                else:
                    logging.info("Checking if {} in {}-{}".format(port,rule['port_range']['from'],rule['port_range']['to']))
                    port_match = rule['port_range']['from'] <= port <= rule['port_range']['to']
                    logging.info("port_match = {}".format(port_match))
                if port_match:
                    for grantee in rule['grantees']:
                        if target_ip['type'] == 'ip':
                            if netaddr.IPAddress(target_ip['value']) in netaddr.IPNetwork(grantee['value']):
                                if rule['allow']:
                                    traffic_allowed = True
                                    match_found = True
                                    logging.info("Traffic Allowed: {} in {}".format(target_ip['value'],grantee['value']))
                                    break
                                else:
                                    match_found = True
                                    break
                        elif target_ip['type'] == 'cidr':
                            if netaddr.IPNetwork(target_ip['value']) in netaddr.IPNetwork(grantee['value']):
                                if rule['allow']:
                                    traffic_allowed = True
                                    match_found = True
                                    logging.info("Traffic Allowed: {} in {}".format(target_ip['value'],grantee['value']))
                                    break
                                else:
                                    match_found = True
                                    break
                    if match_found:
                        break
    elif object_type == 'SG':
        for rule in rule_list:
            if rule['ip_protocol'].lower() in ['all',ip_protocol.lower()]:
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
    try:
        ephemeral_index = config.ephemeral_index
        ephemeral_ports = ephemeral_index[platform.upper()]
    except:
        ephemeral_ports = {'from':1024,'to':65535}
    finally:
        return ephemeral_ports


def format_list(the_list,article='and'):
    if len(the_list) > 1:
        result = "{} {} {}".format(", ".join(the_list[:-1]),article,the_list[-1])
    elif len(the_list) == 1:
        result = the_list[0]
    else:
        result = None
    return result


if __name__ == '__main__':
    if len(sys.argv) == 2:
        troubleshoot(sys.argv[1],sys.argv[2])
    elif len(sys.argv) == 3:
        troubleshoot(sys.argv[1],sys.argv[2],sys.argv[3])
    elif len(sys.argv) == 4:
        troubleshoot(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])
    elif len(sys.argv) == 5:
        troubleshoot(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5])
    elif len(sys.argv) == 6:
        troubleshoot(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5],sys.argv[6])
    else:
        print('Usage:\n> {}'.format(config.usage))