import re
import json
import subprocess
import os

#VARIABLES

#Nombres de los stacks de CloudFormation
nombre_stack_op = "vpc-onpremise"
nombre_stack_nube = "vpc-nube"
stack_name_vpn = "vpn-server"

#Bloques CIDR de las VPC
cidr_vpc_nube = "10.0.0.0/16"
cidr_vpc_onpremise = "172.0.0.0/16"

#Nombre del rol IAM
nombre_rol_iam = "arn:aws:iam::241941632947:role/CloudformationTFGLuis"

#Configuración de la VPN
vendor = "Generic"
ike_version = "ikev1"
aws_region = "eu-west-1"

#Nombres de los secretos de Secrets Manager donde se guardan las PSK
psk_tunnel1_name = "psk_tunnel1.1"
psk_tunnel2_name = "psk_tunnel2.1"


#Se despliega primero la VPC on-premise y luego la VPC cloud
command = "aws cloudformation create-stack --stack-name {} --template-body file://VPCsimulacionOnPremise.yml --tags Key=OPI-Code,Value=008_807102 --capabilities CAPABILITY_IAM --role-arn {}".format(nombre_stack_op, nombre_rol_iam)
subprocess.run(command, shell=True, check=True)

wait_command = "aws cloudformation wait stack-create-complete --stack-name vpc-onpremise"
subprocess.run(wait_command, shell=True, check=True)
print("Éxito desplegando vpc-onpremise")

command = "aws cloudformation create-stack --stack-name {} --template-body file://VPCnube.yml --tags Key=OPI-Code,Value=008_807102 --capabilities CAPABILITY_IAM --role-arn {}".format(nombre_stack_nube, nombre_rol_iam)
subprocess.run(command, shell=True, check=True)

wait_command = "aws cloudformation wait stack-create-complete --stack-name vpc-nube"
subprocess.run(wait_command, shell=True, check=True)
print("Éxito desplegando vpc-nube")

#Saca el ID del Vendor deseado para la conexión VPN
def get_vpn_device_type_id():
    command = "aws ec2 get-vpn-connection-device-types --region eu-west-1"
    output = subprocess.check_output(command, shell=True)
    json_data = json.loads(output)
    device_types = json_data["VpnConnectionDeviceTypes"]

    for device_type in device_types:
        if device_type["Vendor"] == vendor:
            return device_type["VpnConnectionDeviceTypeId"]

    return None

vpn_connection_device_type_id = get_vpn_device_type_id()

#Extrae ID del VPNConnection de la vpc-nube
def get_export_value(export_name):
    command = ["aws", "cloudformation", "list-exports"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode != 0:
        print(f"Error al ejecutar el comando: {result.stderr}")
        return None

    exports = json.loads(result.stdout)
    
    for export in exports["Exports"]:
        if export["Name"] == export_name:
            return export["Value"]
    
    print(f"No se encontró el export con el nombre '{export_name}'")
    return None

vpn_connection_export_name = "vpc-nube-vpnconnection"
vpn_connection_id = get_export_value(vpn_connection_export_name)


#Obtiene el fichero de configuración de la conexión VPN para el vendor y la VPNConnection dados
def get_vpn_connection_device_sample_configuration(vpn_connection_id, vpn_connection_device_type_id, ike_version, aws_region):
    try:
        result = subprocess.run(['aws', 'ec2', 'get-vpn-connection-device-sample-configuration',
                                 '--vpn-connection-id', vpn_connection_id,
                                 '--vpn-connection-device-type-id', vpn_connection_device_type_id,
                                 '--internet-key-exchange-version', ike_version,
                                 '--region', aws_region,
                                 '--output', 'text'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    except Exception as e:
        print("Error:", e)
        return None
    
sample_configuration = get_vpn_connection_device_sample_configuration(vpn_connection_id, vpn_connection_device_type_id, ike_version, aws_region)

#Saca valores del túnel 1

tunnel1_section_pattern = r"(IPSec Tunnel #1.*?)(?=IPSec Tunnel #2)"
tunnel1_section = re.search(tunnel1_section_pattern, sample_configuration, re.DOTALL).group(1)

psk_tunnel1_pattern = r"Pre-Shared Key\s*:\s*([\w._-]+)"
outside_vpg_tunnel1_pattern = r"Virtual Private Gateway\s*:\s*([\d.]+)"
inside_cgw_tunnel1_pattern = r"Customer Gateway\s*:\s*([\d.]+/[\d]+)"
inside_vpg_tunnel1_pattern = r"Virtual Private Gateway\s*:\s*([\d.]+/[\d]+)"
bgp_asn_tunnel1_pattern = r"Virtual Private\s+Gateway ASN\s*:\s*(\d+)"
bgp_neighbour_ip_tunnel1_pattern = r"Neighbor IP Address\s*:\s*([\d.]+)"

bgp_asn_localvpn_pattern = r"Customer\s+Gateway ASN\s*:\s*(\d+)"


psk_tunnel1 = re.search(psk_tunnel1_pattern, tunnel1_section).group(1)
outside_vpg_tunnel1 = re.search(outside_vpg_tunnel1_pattern, tunnel1_section).group(1)
inside_cgw_tunnel1 = re.search(inside_cgw_tunnel1_pattern, tunnel1_section).group(1)
inside_vpg_tunnel1 = re.search(inside_vpg_tunnel1_pattern, tunnel1_section).group(1)
bgp_asn_tunnel1 = re.search(bgp_asn_tunnel1_pattern, tunnel1_section).group(1)
bgp_neighbour_ip_tunnel1 = re.search(bgp_neighbour_ip_tunnel1_pattern, tunnel1_section).group(1)

bgp_asn_localvpn = re.search(bgp_asn_localvpn_pattern, tunnel1_section).group(1)

#Sube la PSK del tunel 1 a SecretsManager 
command = f'aws secretsmanager update-secret --secret-id "{psk_tunnel1_name}" --secret-string \'{{"psk": "{psk_tunnel1}"}}\''
subprocess.run(command, shell=True, check=True)

#Saca valores del túnel 2
tunnel2_section_pattern = r"IPSec Tunnel #2(.*?)Additional Notes and Questions"
tunnel2_section = re.search(tunnel2_section_pattern, sample_configuration, re.DOTALL).group(1)

psk_tunnel2_pattern = r"Pre-Shared Key\s*:\s*([\w._-]+)"
outside_vpg_tunnel2_pattern = r"Virtual Private Gateway\s*:\s*([\d.]+)"
inside_cgw_tunnel2_pattern = r"Customer Gateway\s*:\s*([\d.]+/[\d]+)"
inside_vpg_tunnel2_pattern = r"Virtual Private Gateway\s*:\s*([\d.]+/[\d]+)"
bgp_asn_tunnel2_pattern = r"Virtual Private\s+Gateway ASN\s*:\s*(\d+)"
bgp_neighbour_ip_tunnel2_pattern = r"Neighbor IP Address\s*:\s*([\d.]+)"

psk_tunnel2 = re.search(psk_tunnel2_pattern, tunnel2_section).group(1)
outside_vpg_tunnel2 = re.search(outside_vpg_tunnel2_pattern, tunnel2_section).group(1)
inside_cgw_tunnel2 = re.search(inside_cgw_tunnel2_pattern, tunnel2_section).group(1)
inside_vpg_tunnel2 = re.search(inside_vpg_tunnel2_pattern, tunnel2_section).group(1)
bgp_asn_tunnel2 = re.search(bgp_asn_tunnel2_pattern, tunnel2_section).group(1)
bgp_neighbour_ip_tunnel2 = re.search(bgp_neighbour_ip_tunnel2_pattern, tunnel2_section).group(1)

#Sube la PSK del tunel 2 a SecretsManager
command = f'aws secretsmanager update-secret --secret-id "{psk_tunnel2_name}" --secret-string \'{{"psk": "{psk_tunnel2}"}}\''
subprocess.run(command, shell=True, check=True)


#Saca valores de Local Network Configuration

#Saca el VPC y el subnet ID
def get_id(export_name):
    output = subprocess.check_output(["aws", "cloudformation", "list-exports"])
    exports_data = json.loads(output)
    exports_list = exports_data['Exports']

    for export in exports_list:
        if export['Name'] == export_name:
            return export['Value']

    return None

vpc_id = get_id('vpc-onpremise-id')
public_subnet_id = get_id('public-subnet-id')
private_subnet_id = get_id('eu-west-1-vpc-onpremise-PrivateSubnet')


#Extrae el allocation ID de la EIP que se asociará al VPN Gateway
command = "aws cloudformation list-exports"
result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

if result.returncode != 0:
    print(f"Error al ejecutar el comando: {result.stderr}")
else:
    output = result.stdout
    data = json.loads(output)
    exports = data["Exports"]

    vpn_eip = None
    for export in exports:
        if export["Name"] == "vpn-eip":
            vpn_eip = export["Value"]
            break

    if vpn_eip:
        
        command = f"aws ec2 describe-addresses --filters Name=public-ip,Values={vpn_eip}"
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

        if result.returncode != 0:
            print(f"Error al ejecutar el comando: {result.stderr}")
        else:
            output = result.stdout
            data = json.loads(output)
            addresses = data["Addresses"]

            if len(addresses) > 0:
                allocation_id = addresses[0]["AllocationId"]
            else:
                print("No se encontró un Elastic IP con la dirección IP especificada.")
    else:
        print("No se encontró el recurso 'vpn-eip'.")

#Genera un JSON con todas las variables a pasarle como parámetro a la plantilla de la VPN
def create_parameters_file(psk_tunnel1_name, outside_vpg_tunnel1, inside_cgw_tunnel1, inside_vpg_tunnel1, bgp_asn_tunnel1, bgp_neighbour_ip_tunnel1, psk_tunnel2_name, outside_vpg_tunnel2, inside_cgw_tunnel2, inside_vpg_tunnel2, bgp_asn_tunnel2, allocation_id, bgp_asn_localvpn, bgp_neighbour_ip_tunnel2, vpc_id, public_subnet_id):
    parameters = [
        {
            "ParameterKey": "pOrg",
            "ParameterValue": "vpn"
        },
        {
            "ParameterKey": "pSystem",
            "ParameterValue": "infra"
        },
        {
            "ParameterKey": "pApp",
            "ParameterValue": "vpngw"
        },
        {
            "ParameterKey": "pEnvPurpose",
            "ParameterValue": "test"
        },
        {
            "ParameterKey": "pAuthType",
            "ParameterValue": "psk"
        },
        {
            "ParameterKey": "pTunnel1PskSecretName",
            "ParameterValue": psk_tunnel1_name
        },
        {
            "ParameterKey": "pTunnel1VgwOutsideIpAddress",
            "ParameterValue": outside_vpg_tunnel1
        },
        {
            "ParameterKey": "pTunnel1CgwInsideIpAddress",
            "ParameterValue": inside_cgw_tunnel1
        },
        {
            "ParameterKey": "pTunnel1VgwInsideIpAddress",
            "ParameterValue": inside_vpg_tunnel1
        },
        {
            "ParameterKey": "pTunnel1VgwBgpAsn",
            "ParameterValue": bgp_asn_tunnel1
        },
        {
            "ParameterKey": "pTunnel1BgpNeighborIpAddress",
            "ParameterValue": bgp_neighbour_ip_tunnel1
        },
        {
            "ParameterKey": "pTunnel2PskSecretName",
            "ParameterValue": psk_tunnel2_name
        },
        {
            "ParameterKey": "pTunnel2VgwOutsideIpAddress",
            "ParameterValue": outside_vpg_tunnel2
        },
        {
            "ParameterKey": "pTunnel2CgwInsideIpAddress",
            "ParameterValue": inside_cgw_tunnel2
        },
        {
            "ParameterKey": "pTunnel2VgwInsideIpAddress",
            "ParameterValue": inside_vpg_tunnel2
        },
        {
            "ParameterKey": "pTunnel2VgwBgpAsn",
            "ParameterValue": bgp_asn_tunnel2
        },
        {
            "ParameterKey": "pEipAllocationId",
            "ParameterValue": allocation_id
        },
        {
            "ParameterKey": "pLocalBgpAsn",
            "ParameterValue": bgp_asn_localvpn
        },
        {
            "ParameterKey": "pTunnel2BgpNeighborIpAddress",
            "ParameterValue": bgp_neighbour_ip_tunnel2
        },
        {
            "ParameterKey": "pVpcId",
            "ParameterValue": vpc_id
        },
        {
            "ParameterKey": "pVpcCidr",
            "ParameterValue": cidr_vpc_onpremise
        },
        {
            "ParameterKey": "pSubnetId",
            "ParameterValue": public_subnet_id
        }
    ] 

    with open("parameters.json", "w") as f:
        json.dump(parameters, f)

create_parameters_file(psk_tunnel1_name, outside_vpg_tunnel1, inside_cgw_tunnel1, inside_vpg_tunnel1, bgp_asn_tunnel1, bgp_neighbour_ip_tunnel1, psk_tunnel2_name, outside_vpg_tunnel2, inside_cgw_tunnel2, inside_vpg_tunnel2, bgp_asn_tunnel2, allocation_id, bgp_asn_localvpn, bgp_neighbour_ip_tunnel2, vpc_id, public_subnet_id)

#Despliega el stack de la conexión VPN
command = "aws cloudformation create-stack --stack-name {} --template-body file://vpn-gateway-strongswan.yml --parameters file://parameters.json --tags Key=OPI-Code,Value=008_807102 --capabilities CAPABILITY_NAMED_IAM --role-arn {}".format(stack_name_vpn, nombre_rol_iam)
subprocess.run(command, shell=True, check=True)

wait_command = "aws cloudformation wait stack-create-complete --stack-name vpn-server"
subprocess.run(wait_command, shell=True, check=True)
print("Éxito desplegando servidor VPN")

os.remove("parameters.json")

#Añade ruta onpremise-vpcnube en tabla de rutas de on-premise
command = f"aws cloudformation describe-stack-resources --stack-name {stack_name_vpn} --logical-resource-id rVpnGateway --query 'StackResources[].PhysicalResourceId' --output text"
instance_id = subprocess.check_output(command, shell=True, text=True).strip()

command = f"aws ec2 describe-network-interfaces --filters Name=attachment.instance-id,Values={instance_id} --query 'NetworkInterfaces[].NetworkInterfaceId' --output text"
eni_id = subprocess.check_output(command, shell=True, text=True).strip()

command = f"aws ec2 describe-route-tables --filters Name=association.subnet-id,Values={public_subnet_id} --query 'RouteTables[].RouteTableId' --output text"
public_route_table_id = subprocess.check_output(command, shell=True, text=True).strip()

command = f"aws ec2 create-route --route-table-id {public_route_table_id} --destination-cidr-block {cidr_vpc_nube} --network-interface-id {eni_id}"
subprocess.run(command, shell=True, check=True)

command = f"aws ec2 describe-route-tables --filters Name=association.subnet-id,Values={private_subnet_id} --query 'RouteTables[].RouteTableId' --output text"
private_route_table_id = subprocess.check_output(command, shell=True, text=True).strip()

command = f"aws ec2 create-route --route-table-id {private_route_table_id} --destination-cidr-block {cidr_vpc_nube} --network-interface-id {eni_id}"
subprocess.run(command, shell=True, check=True)
