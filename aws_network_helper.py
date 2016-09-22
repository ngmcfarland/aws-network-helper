from conf import aws_network_helper_config as conf
import check_aws_network
import requests
import logging
import json
import sys
import re

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def lambda_handler(event,context):
    lambda_message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info("Starting Lambda...")
    if lambda_message['command'][0] == '/aws-network':
        logger.info("Slack Slash Command: {}".format(lambda_message['command'][0]))
        if lambda_message['text'][0].upper() == 'HELP':
            response = conf.help_message
        else:
            r = requests.post(lambda_message['response_url'][0],data=json.dumps({'text':'Hold on, let me check some things...'}))
            results = match_input(lambda_message['text'][0])
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
    else:
        response = "I'm sorry, I don't recognize the command: {}".format(command)
    response_body = {'text':response}
    logger.info("Sending response: {}".format(response_body))
    r = requests.post(lambda_message['response_url'][0],data=json.dumps(response_body))
    logger.info("Response from Slack response URL post: {}".format(r.text))


def match_input(user_input):
    logger.debug("Matching text: {}".format(user_input))
    match_found = False
    match1 = re.compile(r"^(why can\'t i|i (can\'t|cannot)|help me|i want to) connect to ([a-z0-9\-\_\+\=\.\:\/\@\s]*) from ([a-z0-9\-\_\+\=\.\:\/\@\s]*) on (tcp|udp|icmp)?\s?port (\d+)\??$", re.IGNORECASE)
    match2 = re.compile(r"^(why can\'t i|i (can\'t|cannot)|help me|i want to) connect to ([a-z0-9\-\_\+\=\.\:\/\@\s]*) from ([a-z0-9\-\_\+\=\.\:\/\@\s]*)\??$", re.IGNORECASE)
    match3 = re.compile(r"^troubleshoot (the|my)?\s?connection between ([a-z0-9\-\_\+\=\.\:\/\@\s]*) and ([a-z0-9\-\_\+\=\.\:\/\@\s]*) on (tcp|udp|icmp)?\s?port (\d+)$",re.IGNORECASE)
    match4 = re.compile(r"^troubleshoot (the|my)?\s?connection between ([a-z0-9\-\_\+\=\.\:\/\@\s]*) and ([a-z0-9\-\_\+\=\.\:\/\@\s]*)$",re.IGNORECASE)
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
    if match_found:
        results = {'match':True,'source':source_instance,'destination':destination_instance,'port':port,'ip_protocol':ip_protocol}
    else:
        results = {'match':False}
    return results