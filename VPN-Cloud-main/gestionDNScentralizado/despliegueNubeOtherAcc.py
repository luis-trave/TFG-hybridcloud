import json
import subprocess
import os
import uuid

#Se extraen las dos ResolverRules y el TGW del RAM
def get_resource_ids(resource_type):
    command = f"aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-type {resource_type}"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    
    if error:
        print(f"Hubo un error al obtener los IDs del recurso: {error}")
        return None

    output_dict = json.loads(output)
    resources = output_dict.get('resources', [])

    if not resources:
        print(f"No se encontraron recursos de tipo: {resource_type}")
        return None

    return [resource['arn'].split("/")[-1] for resource in resources]

tgw_id = get_resource_ids('ec2:TransitGateway')[0]
resolver_rule_ids = get_resource_ids('route53resolver:ResolverRule')

resolver_rule_id_1 = resolver_rule_ids[0]
resolver_rule_id_2 = resolver_rule_ids[1]

print(f"ID del Transit Gateway: {tgw_id}")
print(f"ID de la Regla del Resolver 1: {resolver_rule_id_1}")
print(f"ID de la Regla del Resolver 2: {resolver_rule_id_2}")

#Se despliega la VPC con los parámetros extraidos del RAM
def create_parameters_file(resolver_rule_id_1, resolver_rule_id_2, tgw_id):
    parameters = [
        {
            "ParameterKey": "VpcCIDR",
            "ParameterValue": "192.168.32.0/20"
        },
        {
            "ParameterKey": "PrivateSubnetCIDR",
            "ParameterValue": "192.168.32.0/21"
        },
        {
            "ParameterKey": "PublicSubnetCIDR",
            "ParameterValue": "192.168.40.0/21"
        },
        {
            "ParameterKey": "RuleToCloud",
            "ParameterValue": resolver_rule_id_1
        },
        {
            "ParameterKey": "RuleToOnPrem",
            "ParameterValue": resolver_rule_id_2
        },
        {
            "ParameterKey": "TransitGWId",
            "ParameterValue": tgw_id
        },
        {
            "ParameterKey": "VPCName",
            "ParameterValue": "vpc-luis-nube3"
        },
    ]

    with open("parameters.json", "w") as f:
        json.dump(parameters, f)
create_parameters_file(resolver_rule_id_1, resolver_rule_id_2, tgw_id)

stack_name_nube = "vpc-luis-nube3"
nombre_rol_iam = "arn:aws:iam::727426416106:role/CloudformationTFGLuis"

command = "aws cloudformation create-stack --stack-name {} --template-body file://VPCnubes_otheracc.yml --parameters file://parameters.json --tags Key=OPI-Code,Value=008_807102 --capabilities CAPABILITY_NAMED_IAM --role-arn {}".format(stack_name_nube, nombre_rol_iam)
subprocess.run(command, shell=True, check=True)

wait_command = "aws cloudformation wait stack-create-complete --stack-name vpc-luis-nube3"
subprocess.run(wait_command, shell=True, check=True)
print("Éxito desplegando VPC")
os.remove("parameters.json")

#Se crea la hosted zone y se asocia a la vpc recien desplegada
def get_export_value(export_name):
    command = ["aws", "cloudformation", "list-exports"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    exports = json.loads(result.stdout)
    
    for export in exports["Exports"]:
        if export["Name"] == export_name:
            return export["Value"]
    
    print(f"No se encontró el export con el nombre '{export_name}'") 
    return None

vpc3_exportname = "vpc-luis-nube3-ia"
vpc3_id = get_export_value(vpc3_exportname)
caller_reference = str(uuid.uuid4())

command = f"aws route53 create-hosted-zone --name zone3.awscloud.iic --caller-reference {caller_reference} --vpc VPCRegion=eu-west-1,VPCId={vpc3_id} --hosted-zone-config Comment='Hosted Zone for VPC-nube3',PrivateZone=true"
subprocess.run(command, shell=True, check=True)

def get_hosted_zone_id(zone_name):
    command = "aws route53 list-hosted-zones"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True, encoding='utf-8')
    output, error = process.communicate()

    output_dict = json.loads(output)
    for zone in output_dict['HostedZones']:
        if zone['Name'] == zone_name:
            return zone['Id'].replace("/hostedzone/", "")

    print(f"No se encontró una Hosted Zone con el nombre: {zone_name}")
    return None

hosted_zone_id = get_hosted_zone_id("zone3.awscloud.iic.")
print(f"ID de la Hosted Zone: {hosted_zone_id}")

#CAMBIA A PERFIL DEA
def set_aws_profile(profile_name):
    os.environ['AWS_PROFILE'] = profile_name
set_aws_profile('luis.trave-dea')

command = "aws sts get-caller-identity"
subprocess.run(command, shell=True, check=True)

#Saca ID de la VPC-DNS

def get_export_value(export_name):
    command = ["aws", "cloudformation", "list-exports"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    exports = json.loads(result.stdout)
    
    for export in exports["Exports"]:
        if export["Name"] == export_name:
            return export["Value"]
    
    print(f"No se encontró el export con el nombre '{export_name}'") 
    return None

vpc_dns_exportname = "eu-west-1-vpc-dns-VPC"
vpc_dns_id = get_export_value(vpc_dns_exportname)
print(f"ID de VPC-DNS: {vpc_dns_id}")

#CAMBIA A PERFIL IA
def set_aws_profile(profile_name):
    os.environ['AWS_PROFILE'] = profile_name
set_aws_profile('luis.trave-ia')

command = "aws sts get-caller-identity"
subprocess.run(command, shell=True, check=True)

#Segun tutorial, autoriza el vincular la VPC-DNS a la hosted zone de nube3
command = f"aws route53 create-vpc-association-authorization --hosted-zone-id {hosted_zone_id} --vpc VPCRegion=eu-west-1,VPCId={vpc_dns_id}"
subprocess.run(command, shell=True, check=True)
print("Asociacion autorizada entre hostedzone y VPC-DNS")

#Cambiando a DEA, asociamos la VPC-DNS a la hosted zone de nube3
set_aws_profile('luis.trave-dea')
command=  f"aws route53 associate-vpc-with-hosted-zone --hosted-zone-id {hosted_zone_id} --vpc VPCRegion=eu-west-1,VPCId={vpc_dns_id}"
subprocess.run(command, shell=True, check=True)
print("Asociación exitosa")

#Se añaden rutas desde vpc-onprem y vpc-dns a esta vpc
vpc_dns_id = get_export_value(vpc_dns_exportname)
vpc_onprem_id = get_export_value("vpc-onpremise-id")

stack_name_vpn = "vpn-server"
command = f"aws cloudformation describe-stack-resources --stack-name {stack_name_vpn} --logical-resource-id rVpnGateway --query 'StackResources[].PhysicalResourceId' --output text"
instance_id = subprocess.check_output(command, shell=True, text=True).strip()

command = f"aws ec2 describe-network-interfaces --filters Name=attachment.instance-id,Values={instance_id} --query 'NetworkInterfaces[].NetworkInterfaceId' --output text"
eni_id = subprocess.check_output(command, shell=True, text=True).strip()

onprem_public_subnet_id = get_export_value("public-subnet-id")
onprem_private_subnet_id = get_export_value('eu-west-1-vpc-onpremise-PrivateSubnet')
dns_public_subnet_id = get_export_value("eu-west-1-vpc-dns-PublicSubnet0")
dns_private_subnet_id = get_export_value("eu-west-1-vpc-dns-PrivateSubnet0")

vpc_cidr = "192.168.32.0/20"

command = f"aws ec2 describe-route-tables --filters Name=association.subnet-id,Values={onprem_public_subnet_id} --query 'RouteTables[].RouteTableId' --output text"
onprem_public_route_table_id = subprocess.check_output(command, shell=True, text=True).strip()
command = f"aws ec2 describe-route-tables --filters Name=association.subnet-id,Values={onprem_private_subnet_id} --query 'RouteTables[].RouteTableId' --output text"
onprem_private_route_table_id = subprocess.check_output(command, shell=True, text=True).strip()
command = f"aws ec2 describe-route-tables --filters Name=association.subnet-id,Values={dns_public_subnet_id} --query 'RouteTables[].RouteTableId' --output text"
dns_public_route_table_id = subprocess.check_output(command, shell=True, text=True).strip()
command = f"aws ec2 describe-route-tables --filters Name=association.subnet-id,Values={dns_private_subnet_id} --query 'RouteTables[].RouteTableId' --output text"
dns_private_route_table_id = subprocess.check_output(command, shell=True, text=True).strip()

command = f"aws ec2 create-route --route-table-id {onprem_public_route_table_id} --destination-cidr-block {vpc_cidr} --network-interface-id {eni_id}"
subprocess.run(command, shell=True, check=True)

command = f"aws ec2 create-route --route-table-id {onprem_private_route_table_id} --destination-cidr-block {vpc_cidr} --network-interface-id {eni_id}"
subprocess.run(command, shell=True, check=True)

command = f"aws ec2 create-route --route-table-id {dns_public_route_table_id} --destination-cidr-block {vpc_cidr} --transit-gateway-id {tgw_id}"
subprocess.run(command, shell=True, check=True)

command = f"aws ec2 create-route --route-table-id {dns_private_route_table_id} --destination-cidr-block {vpc_cidr} --transit-gateway-id {tgw_id}"
subprocess.run(command, shell=True, check=True)
