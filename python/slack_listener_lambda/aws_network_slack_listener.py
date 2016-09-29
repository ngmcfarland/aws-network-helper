import re
import json
import boto3
import base64
import urlparse


def lambda_handler(event, context):
    params = urlparse.parse_qs(event['body'])

    conf = get_config()
    expected_token = decrypt_config_value(conf['slack_token'],conf['kms_region'])
    
    sns_client = boto3.client('sns')
    if params['token'][0] != expected_token:
        raise Exception("Invalid request!")
    slack_response_url = encrypt_config_value(params['response_url'][0],conf['kms_key_alias'],conf['kms_region'])
    event_text = re.sub(r'[^\x00-\x7F]+','', params['text'][0])
    slack_event = {'response_type':'SLACK','command':params['command'][0],'text':event_text,'response_url':slack_response_url}
    sns_message = {'default':'I received a message','lambda':json.dumps(slack_event)}
    response = sns_client.publish(TopicArn=conf['sns_arn'],Message=json.dumps(sns_message),MessageStructure='json')
    if 'MessageId' in response:
        return 0
    else:
        raise Exception("Failed to publish message to SNS")


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


def encrypt_config_value(unencrypted_value,key_alias,region):
    kms_client = boto3.client('kms',region_name=region)
    response = kms_client.encrypt(KeyId='alias/{}'.format(key_alias),Plaintext=unencrypted_value)
    return base64.b64encode(response['CiphertextBlob'])