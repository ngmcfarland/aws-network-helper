from conf import aws_network_helper_config as conf
import check_aws_network
import requests
import logging
import base64
import boto3
import json
import sys
import re

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def lambda_handler(event,context):
    if 'Records' in event:
        message_body = json.loads(event['Records'][0]['Sns']['Message'])
    else:
        if isinstance(event,str):
            message_body = json.loads(event)
        elif isinstance(event,dict):
            message_body = event
    logger.info("Starting Lambda...")
    s3_conf = get_config()
    if message_body['response_type'].upper() == 'SLACK':
        slack_response_url = decrypt_config_value(message_body['response_url'],s3_conf['kms_region'])
        if not validate_slack_domain(slack_response_url):
            raise Exception("Invalid Slack Response URL!")
        if not message_body['command'] == s3_conf['slack_command']:
            response = "I'm sorry, I don't recognize the command: {}".format(command)
        logger.info("Slack Slash Command: {}".format(message_body['command']))
    if message_body['text'].upper() == 'HELP':
        response = conf.help_message
    else:
        if message_body['response_type'].upper() == 'SLACK':
            r = requests.post(slack_response_url,data=json.dumps({'text':'Hold on, let me check some things...'}))
        results = match_input(message_body['text'])
        logger.debug("Results from match_input: {}".format(results))
        if results['match']:
            if results['source'] and results['destination'] and results['port'] and results['ip_protocol']:
                response = check_aws_network.troubleshoot(source_name=results['source'],destination_name=results['destination'],port=results['port'],ip_protocol=results['ip_protocol'])
            elif results['source'] and results['destination'] and results['port']:
                response = check_aws_network.troubleshoot(source_name=results['source'],destination_name=results['destination'],port=results['port'])
            else:
                response = check_aws_network.troubleshoot(source_name=results['source'],destination_name=results['destination'])
        else:
            response = "I'm sorry, I don't recognize what you're asking."
    if message_body['response_type'].upper() == 'SLACK':
        response_body = {'text':response}
        logger.info("Sending response: {}".format(response_body))
        r = requests.post(slack_response_url,data=json.dumps(response_body))
        logger.info("Response from Slack response URL post: {}".format(r.text))
    elif message_body['response_type'].upper() == 'RETURN':
        logger.info("Sending response: {}".format(response))
        return response


def get_config():
    sts_client = boto3.client('sts')
    response = sts_client.get_caller_identity()
    s3_bucket = "aws-network-helper-{}".format(response['Account'])
    s3 = boto3.resource('s3')
    s3_object = s3.Object(s3_bucket,'conf/aws-network-helper-config.json')
    contents = json.loads(s3_object.get()['Body'].read())
    return contents


def decrypt_config_value(encrypted_value,region):
    kms_client = boto3.client('kms',region_name=region)
    return kms_client.decrypt(CiphertextBlob=base64.b64decode(encrypted_value))['Plaintext']


def validate_slack_domain(response_url):
    slack_domain = re.compile(r"^https://hooks.slack.com/.*",re.IGNORECASE)
    return True if slack_domain.match(response_url) else False


def match_input(user_input):
    logger.debug("Matching text: {}".format(user_input))
    match_found = False
    match1 = re.compile(r"^(why can I not|why cant i|i (cant|cannot)|help me|i want to) connect to ([a-z0-9\-\_\+\=\.\:\/\@\s]*) from ([a-z0-9\-\_\+\=\.\:\/\@\s]*) on (tcp|udp|icmp)?\s?port (\d+)\??\.?$", re.IGNORECASE)
    match2 = re.compile(r"^(why can I not|why cant i|i (cant|cannot)|help me|i want to) connect to ([a-z0-9\-\_\+\=\.\:\/\@\s]*) from ([a-z0-9\-\_\+\=\.\:\/\@\s]*)\??\.?$", re.IGNORECASE)
    match3 = re.compile(r"^troubleshoot (the|my)?\s?connection between ([a-z0-9\-\_\+\=\.\:\/\@\s]*) and ([a-z0-9\-\_\+\=\.\:\/\@\s]*) on (tcp|udp|icmp)?\s?port (\d+)\.?$",re.IGNORECASE)
    match4 = re.compile(r"^troubleshoot (the|my)?\s?connection between ([a-z0-9\-\_\+\=\.\:\/\@\s]*) and ([a-z0-9\-\_\+\=\.\:\/\@\s]*)\.?$",re.IGNORECASE)
    match5 = re.compile(r"^(why can I not|why cant i|i (cant|cannot)|help me|i want to) connect to ([a-z0-9\-\_\+\=\.\:\/\@\s]*) on (tcp|udp|icmp)?\s?port (\d+)\.?\??$",re.IGNORECASE)
    match6 = re.compile(r"^(why can I not|why cant i|i (cant|cannot)|help me|i want to) connect to ([a-z0-9\-\_\+\=\.\:\/\@\s]*)\.?\??$",re.IGNORECASE)
    if match1.match(user_input):
        result = match1.match(user_input)
        source_instance = result.group(4)
        destination_instance = result.group(3)
        ip_protocol = result.group(5)
        port = int(result.group(6))
        match_found = True
    elif match2.match(user_input):
        result = match2.match(user_input)
        source_instance = result.group(4)
        destination_instance = result.group(3)
        ip_protocol = None
        port = None
        match_found = True
    elif match3.match(user_input):
        result = match3.match(user_input)
        source_instance = result.group(2)
        destination_instance = result.group(3)
        ip_protocol = result.group(4)
        port = int(result.group(5))
        match_found = True
    elif match4.match(user_input):
        result = match4.match(user_input)
        source_instance = result.group(2)
        destination_instance = result.group(3)
        ip_protocol = None
        port = None
        match_found = True
    elif match5.match(user_input):
        result = match5.match(user_input)
        source_instance = 'my computer'
        destination_instance = result.group(3)
        ip_protocol = result.group(4)
        port = result.group(5)
        match_found = True
    elif match6.match(user_input):
        result = match6.match(user_input)
        source_instance = 'my computer'
        destination_instance = result.group(3)
        ip_protocol = None
        port = None
        match_found = True
    if match_found:
        results = {'match':True,'source':source_instance,'destination':destination_instance,'port':port,'ip_protocol':ip_protocol}
    else:
        results = {'match':False}
    return results