#!/bin/bash
## Author: Dang Thanh Phat
## Email: thanhphatit95@gmail.com
## Web/blogs: www.itblognote.com
## Description:
##      Path working: kubernetes/digital-ocean/staging-cq-k8s/web-nginx/secrets-staging.yml
##                    <service>/<service-provider>/<service-identifier>/<app_name>
##
## TODOs:
##      - Check tool need to use in this script

#### GLOBAL SETTING SHELL
set -o pipefail
# set -e ### When you use -e it will export error when logic function fail, example grep "yml" if yml not found

####################
# GLOBAL VARIABLES #
####################

#### VARIABLES

ACTION="${1:-plan}"
METHOD="${2:-azure}" # Valid value: aws / azure / digital-ocean / vng-cloud
DEBUG="${3:-+x}"

### Use flag -x with set to debug and show log command, and +x to hide
set ${DEBUG};

SCAN_ALL_FILES="${SCAN_ALL_FILES:-false}"

URL_K8S_CONFIG="${URL_K8S_CONFIG:-none}"

RESTART_NS_BLACKLIST="${RESTART_NS_BLACKLIST:-none}"

CURRENT_BRANCH="main"
MAIN_BRANCH="main"

#TMPFILE_LIST_YAML=$(mktemp /tmp/tempfile-list-yaml-XXXXXXXX)
TMPFILE_LIST_YAML=$(mktemp /tmp/tempfile-list-yaml-XXXXXXXX)
TMPFILE_LIST_PROVIDERS="${TMPFILE_LIST_YAML}.providers"
TMPFILE_LIST_YAML_DIRS="${TMPFILE_LIST_YAML}.parent-dirs"
TMPFILE_LISTFILES_COMPARE=$(mktemp /tmp/tempfile-list-yaml-compare-branch-XXXXXXXX)

# WARNING IGNORE LIST
IGNORE_WARN_1="Warning: kubectl apply should be used on resource created by either kubectl create --save-config or kubectl apply"

### Used with echo have flag -e
RLC="\033[1;31m"    ## Use redlight color
GC="\033[0;32m"     ## Use green color
YC="\033[0;33m"     ## Use yellow color
BC="\033[0;34m"     ## Use blue color
EC="\033[0m"        ## End color with no color

#### FUNCTIONS

function check_var(){
    local VAR_LIST=(${1})

    for var in ${VAR_LIST[@]}; do
        if [[ -z "$(eval echo $(echo $`eval echo "${var}"`))" ]];then
            echo -e "${YC}[CAUTIONS] Variable ${var} not found!"
            exit 1
        fi
    done

    #### Example: check_var "DEVOPS THANHPHATIT"
}

function pre_check_dependencies(){
    ## All tools used in this script
    local TOOLS_LIST=(${1})

    for tools in ${TOOLS_LIST[@]}; do
        # If not found tools => exit
        if [[ ! $(command -v ${tools}) ]];then
cat << ALERTS
[x] Not found tool [${tools}] on machine.

Exit.
ALERTS
            exit 1
        fi
    done

    #### Example: pre_check_dependencies "helm" 
}

function check_plugin(){
    local COMMAND_PLUGIN_LIST="${1}"
    local PLUGIN_LIST=(${2})

    local TOOLS_NAME="$(echo "${COMMAND_PLUGIN_LIST}" | awk '{print $1}')"

    for plugin in ${PLUGIN_LIST[@]}; do
        # If not found tools => exit
        if [[ ! $(${COMMAND_PLUGIN_LIST} 2>/dev/null | grep -i "^${plugin}") ]];then
cat << ALERTS
[x] Not found this ${TOOLS_NAME} plugin [${plugin}] on machine.

Exit.
ALERTS
            exit 1
        fi
    done

    #### Example: check_plugin "helm plugin list" "cm-push diff s3" 
}

function compare_versions() {
    local VERSION_01=${1}
    local VERSION_02=${2}

    if [[ ${VERSION_01} == ${VERSION_02} ]]; then
        echo "equal"
    else
        local IFS=.
        local ver1=(${VERSION_01})
        local ver2=(${VERSION_02})

        local len=${#ver1[@]}
        for ((i=0; i<len; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            ver2[i]=0
        fi

        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            echo "less"
            return
        fi

        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            echo "greater"
            return
        fi
        done

        echo "equal"
    fi
}

function about(){
cat <<ABOUT

*********************************************************
* Author: DANG THANH PHAT                               *
* Email: thanhphat@itblognote.com                       *
* Blog: www.itblognote.com                              *
* Version: 1.5                                          *
* Purpose: Tools to deploy secrets or configmaps to k8s *
*********************************************************

Use --help or -h to check syntax, please !

ABOUT
    exit 1
}

function help(){
cat <<HELP

Usage: k8s-apply-config [options...] [method...] [debug...]

[*] OPTIONS:
    -h, --help              Show help
    -v, --version           Show info and version
    apply                   Start find secrets and configmaps in source git to apply to K8S
    plan                    (This is default value) - plan will have people know what will happen

[*] METHOD:
    azure                   Apply to service aks of Azure
    aws                     Apply to service eks of AWS
    digital-ocean           Apply to service oks of Digital Ocean
    vng-cloud               Apply to service vks of VNG Cloud

[*] DEBUG: (Support for DevOps code, default value is +x)
    -x, +x                  Use flag -x with set to debug and show log command contrary +x to hide

HELP
    exit 1
}

# Pre-check
function init() {
    if [[ ! -f ${TMPFILE_LIST_YAML} ]];then
        touch ${TMPFILE_LIST_YAML}
    fi

    if [[ ! -f ${TMPFILE_LIST_PROVIDERS} ]];then
        touch ${TMPFILE_LIST_PROVIDERS}
    fi

    if [[ ! -f ${TMPFILE_LIST_YAML_DIRS} ]];then
        touch ${TMPFILE_LIST_YAML_DIRS}
    fi
    
    if [[ ! -f ${TMPFILE_LISTFILES_COMPARE} ]];then
        touch ${TMPFILE_LISTFILES_COMPARE}
    fi
}

function cleanup() {
    # Delete tempfile
    if [[ -f ${TMPFILE_LIST_YAML} ]];then
        rm -f ${TMPFILE_LIST_YAML}
    fi

    if [[ -f ${TMPFILE_LIST_PROVIDERS} ]];then
        rm -f ${TMPFILE_LIST_PROVIDERS}
    fi

    if [[ -f ${TMPFILE_LIST_YAML_DIRS} ]];then
        rm -f ${TMPFILE_LIST_YAML_DIRS}
    fi

    if [[ -f ${TMPFILE_LISTFILES_COMPARE} ]];then
        rm -f ${TMPFILE_LISTFILES_COMPARE}
    fi

    if [[ -f ./config ]];then
        rm -f ./config
    fi
}

function download_file(){
    local DOWN_USER=${1}
    local DOWN_PASSWORD=${2}
    local DOWN_FILE_EXPORT_NAME=${3}
    local DOWN_URL=${4}

    curl -u ${DOWN_USER}:${DOWN_PASSWORD} -o ${DOWN_FILE_EXPORT_NAME} ${DOWN_URL} &
    wait

    if [[ -f ${DOWN_FILE_EXPORT_NAME} ]];then
        echo -e "${GC}[DOWNLOAD]: ${DOWN_FILE_EXPORT_NAME} SUCCESS ****"
    else
        echo -e "${RLC}[ERROR] not found download file!"
    fi
}

function generate_aws_credentials(){
    # This scripts is used to login multiple aws profile credentials

    echo ""
    echo "-------------------------------------"
    echo "|   AWS PROFILE CREDENTIALS SETUP   |"
    echo "-------------------------------------"

    echo "[*] AWS Credentials Setup"

    TMPFILE=$(mktemp /tmp/tempfile-XXXXXXXX)
    TMPDIR_AWS_LOGIN=$(mktemp -d /tmp/aws-credentials-login-XXXXXX)

    # Cleanup
    rm -f "${TMPDIR_AWS_LOGIN}/*"

    # Read each file metadata.conf to get IAM Profile
    echo "[*] Development Status: $DEV_STATUS"
    echo "[*] Staging Status: $STAG_STATUS"
    echo "[*] Production Status: $PROD_STATUS"
    for metafile in `find environments/ -type f -iname "metadata.conf"`
    do
        # if found file metadata.conf has attribute: service_provider: aws
        # means we have config for aws service
        SERVICE_PROVIDER=$(grep "service_provider" ${metafile} | awk -F':' '{print $2}' | tr -d ' ')
        SERVICE_ENVIRONMENT=$(grep "environment" ${metafile} | awk -F':' '{print $2}' | tr -d ' ')
        

        if [[ "${SERVICE_PROVIDER}" == "aws" ]];then
            # e.g aws_profile: <env>-eks-deployment
            if [ $DEV_STATUS == "true" ] && [ ${SERVICE_ENVIRONMENT} == "development" ];then
                echo "${SERVICE_ENVIRONMENT}" >> ${TMPDIR_AWS_LOGIN}/environment
            elif [ $STAG_STATUS == "true" ] && [ ${SERVICE_ENVIRONMENT} == "staging" ];then
                echo "${SERVICE_ENVIRONMENT}" >> ${TMPDIR_AWS_LOGIN}/environment
            elif [ $PROD_STATUS == "true" ] && [ ${SERVICE_ENVIRONMENT} == "production" ];then
                echo "${SERVICE_ENVIRONMENT}" >> ${TMPDIR_AWS_LOGIN}/environment
            fi
        fi
    done

    # Uniq environment for aws infra
    cat ${TMPDIR_AWS_LOGIN}/environment | sort | uniq > ${TMPDIR_AWS_LOGIN}/environment.tmp
    rm -f ${TMPDIR_AWS_LOGIN}/environment
    mv ${TMPDIR_AWS_LOGIN}/environment.tmp ${TMPDIR_AWS_LOGIN}/environment

    # Get credentials for each env
    echo ""
    if [[ "$(cat ${TMPDIR_AWS_LOGIN}/environment | wc -l | tr -d ' ')" -gt 0 ]];then
        while read env
        do
            echo "[+] Environment: ${env}"

            if [[ "${env}" == "development" || "${env}" == "dev" || "${env}" == "develop" ]];then
                # Check env
                if [[ ! "$(env | grep -i "DEV_AWS_ACCESS_KEY_ID")" ]];then
                    echo "[x] Cannot find ENV VAR: DEV_AWS_ACCESS_KEY_ID"
                    exit 1
                fi

                if [[ ! "$(env | grep -i "DEV_AWS_SECRET_ACCESS_KEY")" ]];then
                    echo "[x] Cannot find ENV VAR: DEV_AWS_SECRET_ACCESS_KEY"
                    exit 1
                fi

                AWS_ACCESS_KEY_ID="${DEV_AWS_ACCESS_KEY_ID}"
                AWS_SECRET_ACCESS_KEY="${DEV_AWS_SECRET_ACCESS_KEY}"
                AWS_REGION="${AWS_DEFAULT_REGION:-ap-southeast-1}"

            elif [[ "${env}" == "staging" || "${env}" == "stag" || "${env}" == "stg" ]];then
                # Check env
                if [[ ! "$(env | grep -i "STG_AWS_ACCESS_KEY_ID")" ]];then
                    echo "[x] Cannot find ENV VAR: STG_AWS_ACCESS_KEY_ID"
                    exit 1
                fi

                if [[ ! "$(env | grep -i "STG_AWS_SECRET_ACCESS_KEY")" ]];then
                    echo "[x] Cannot find ENV VAR: STG_AWS_SECRET_ACCESS_KEY"
                    exit 1
                fi

                AWS_ACCESS_KEY_ID="${STG_AWS_ACCESS_KEY_ID}"
                AWS_SECRET_ACCESS_KEY="${STG_AWS_SECRET_ACCESS_KEY}"
                AWS_REGION="${AWS_DEFAULT_REGION:-ap-southeast-1}"

            elif [[ "${env}" == "production" || "${env}" == "prod" || "${env}" == "prd"  ]];then
                # Check env
                if [[ ! "$(env | grep -i "PROD_AWS_ACCESS_KEY_ID")" ]];then
                    echo "[x] Cannot find ENV VAR: PROD_AWS_ACCESS_KEY_ID"
                    exit 1
                fi

                if [[ ! "$(env | grep -i "PROD_AWS_SECRET_ACCESS_KEY")" ]];then
                    echo "[x] Cannot find ENV VAR: PROD_AWS_SECRET_ACCESS_KEY"
                    exit 1
                fi

                AWS_ACCESS_KEY_ID="${PROD_AWS_ACCESS_KEY_ID}"
                AWS_SECRET_ACCESS_KEY="${PROD_AWS_SECRET_ACCESS_KEY}"
                AWS_REGION="${AWS_DEFAULT_REGION:-ap-southeast-1}"
            fi

            # Configure AWS Profile
            AWS_ENV_IAM_PROFILE="${env}-eks-deployment"
            aws configure set --profile ${AWS_ENV_IAM_PROFILE} region ${AWS_REGION}
            aws configure set --profile ${AWS_ENV_IAM_PROFILE} aws_access_key_id ${AWS_ACCESS_KEY_ID}
            aws configure set --profile ${AWS_ENV_IAM_PROFILE} aws_secret_access_key ${AWS_SECRET_ACCESS_KEY}

            AWS_CALLER_IDENTITY=$(aws sts get-caller-identity --profile ${AWS_ENV_IAM_PROFILE} --output text)
            if [[ ! $(echo $AWS_CALLER_IDENTITY | grep -Ei "develop|dev|stg|staging|prod|prd" ) ]];then
                echo "[x] Verify: AWS Result from [sts get-caller-identity] does not match env"
                echo "[-] Result: ${AWS_CALLER_IDENTITY}"
                exit 1
            else
                echo "[+] Setup AWS IAM Profile: ${AWS_ENV_IAM_PROFILE} successful"
            fi

        done < ${TMPDIR_AWS_LOGIN}/environment
    else
        echo "[x] Do not find any configuration for AWS Environment Infra"
    fi
}

function pre_checking()
{
    # What is our ACTION & METHOD
    echo "[+] ACTION: ${ACTION}"
    echo "[+] METHOD: ${METHOD}"

    pre_check_dependencies "helm"
    # Check if we miss credentials for AWS S3 Plugin
    if [[ "${METHOD}" == "aws" ]];then
        generate_aws_credentials

        local FLAG_FOUND_AWS_CREDS="false"

        # We need to check available AWS Credentials
        if [[ "$(env | grep -i AWS_PROFILE | awk -F'=' '{print $2}')" != "" ]];then
            FLAG_FOUND_AWS_CREDS="true"
        elif [[ "$(env | grep -i DEFAULT_AWS_PROFILE | awk -F'=' '{print $2}')" != "" ]];then
            FLAG_FOUND_AWS_CREDS="true"
        elif [[ "$(env | grep -wE "AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_DEFAULT_REGION" | wc -l | tr -d ' ')" == "3" ]];then
            FLAG_FOUND_AWS_CREDS="true"
        fi

        if [[ "${FLAG_FOUND_AWS_CREDS}" == "false" ]];then
            echo ""
            echo -e "${RC}[x] CHECKING: cannot find AWS Credentials when you want to use Helm S3 Plugin"
            exit 1
        fi
    elif [[ "${METHOD}" == "vng-cloud" ]];then
        echo "Not code"
        exit 1
    elif [[ "${METHOD}" == "digital-ocean" ]];then
        echo "Not code"
        exit 1
    elif [[ "${METHOD}" == "azure" ]];then

        if [[ "${URL_K8S_CONFIG}" != "none" ]];then
            check_var "URL_USER URL_PASSWORD"
        else
            # Check if we miss credentials for http with cregs
            FLAG_FOUND_AZ_CREDS="false"
            pre_check_dependencies "az"
            if [[ ${AZ_USER} != "" && ${AZ_PASSWORD} != "" ]];then
                FLAG_FOUND_AZ_CREDS="true"
            fi

            if [[ "${FLAG_FOUND_AZ_CREDS}" == "false" ]];then
                echo ""
                echo -e "${RC}[x] CHECKING: cannot find AZ Credentials when you want to use Helm on Azure ACR to deploy K8S"
                exit 1
            fi
        fi

    fi
}

function kubernetes_auth_login() {
    local _SERVICE_PROVIDER="$1"
    local _SERVICE_TYPE="$2"
    local _SERVICE_IDENTIFIER="$3"
    local _SERVICE_CONTEXT="$4"
    local _SERVICE_ENVIRONMENT="$5"

    # Banner
    echo "[*] Kubernetes Authentication Login Process"

    # Check args
    if [[ -z ${_SERVICE_PROVIDER} ]];then
        echo "[x] Cannot find SERVICE_PROVIDER: $_SERVICE_PROVIDER"
        exit 1
    fi

    if [[ -z ${_SERVICE_TYPE} ]];then
        echo "[x] Cannot find SERVICE_TYPE: $_SERVICE_TYPE"
        exit 1
    fi

    if [[ -z ${_SERVICE_IDENTIFIER} ]];then
        echo "[x] Cannot find SERVICE_IDENTIFIER: $_SERVICE_IDENTIFIER"
        exit 1
    fi

    if [[ -z ${_SERVICE_CONTEXT} ]];then
        echo "[x] Cannot find SERVICE_CONTEXT: $_SERVICE_CONTEXT"
        exit 1
    fi

    if [[ -z ${_SERVICE_ENVIRONMENT} ]];then
        echo "[x] Cannot find SERVICE_CONTEXT: $_SERVICE_ENVIRONMENT"
        exit 1
    fi

    [ -d ${HOME}/.kube ] && rm -rf ${HOME}/.kube
    mkdir ${HOME}/.kube

    # Proceed Kubernetes Authentication Login
    if [[ "${_SERVICE_PROVIDER}" == "digital-ocean" ]];then
        echo "****************************"
        echo "*       DIGITAL OCEAN      *"
        echo "****************************"
        echo "[-] Digital Ocean: Authenticating api with TOKEN"

        pre_check_dependencies "doctl"
        # We need to hide AccessToken when this script show it in terminal output
        doctl auth init --access-token ${DIGITAL_OCEAN_TOKEN} 1> /dev/null
        local _status_doctl_auth="$?"
        if [[ ${_status_doctl_auth} -eq 0 ]];then
            echo "[-] Status login: successful"
        else
            echo "[-] Status login: failed"
            exit 1
        fi

        echo "[-] Digital Ocean: get kubeconfig for kubernetes cluster [$_SERVICE_IDENTIFIER]"
        doctl kubernetes cluster kubeconfig save ${_SERVICE_IDENTIFIER}

        echo "[-] Kubectl config current-contenxt information: "
        kubectl config current-context

    elif [[ "${_SERVICE_PROVIDER}" == "vng-cloud" && "${_SERVICE_TYPE}" == "kubernetes" ]];then
        echo "**************************"
        echo "*        VNG CLOUD       *"
        echo "**************************"
        echo "[-] VNG Cloud: Authenticating api with Configfile"
        echo ""
        [ -f $HOME/.kube/config ] && cp ./config $HOME/.kube/config || echo "File does not exist"

        echo "[-] Kubectl config current-contenxt information: "
        kubectl config current-context

    elif [[ "${_SERVICE_PROVIDER}" == "aws" && "${_SERVICE_TYPE}" == "eks" ]];then
        echo "**************************"
        echo "*        AWS CLOUD       *"
        echo "**************************"

        echo "[-] EKS: authenticate and generate kubeconfig with IAM Authenticator AWS Profile [${_SERVICE_IDENTIFIER}]"

        AWS_ENV_IAM_PROFILE="${_SERVICE_ENVIRONMENT}-eks-deployment"
        AWS_ACCOUNT_ID=$(aws sts get-caller-identity --profile ${AWS_ENV_IAM_PROFILE} --output text  | awk '{print $1}' | tr -d ' ')
        EKS_CLUSTER_ASSUME_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/role-eks-deployment-${_SERVICE_IDENTIFIER}"

        # Update kubeconfig
        FAILED_MSG="Cannot generate kubeconfig about EKS Cluster ${_SERVICE_IDENTIFIER}. Exit."
        aws eks update-kubeconfig \
            --name ${_SERVICE_IDENTIFIER} \
            --region ap-southeast-1 \
            --profile ${AWS_ENV_IAM_PROFILE} \
            --role-arn ${EKS_CLUSTER_ASSUME_ROLE_ARN}

        cmdstatus $? "${FAILED_MSG}"
        chmod go-r ~/.kube/config

        echo "[-] EKS: kubectl config current-contenxt information"
        kubectl config current-context

    elif [[ "${_SERVICE_PROVIDER}" == "azure" && "${_SERVICE_TYPE}" == "aks" ]];then
        echo "****************************"
        echo "*        AZURE CLOUD       *"
        echo "****************************"

        echo "[-] Azure: Authenticating api with Configfile"
        echo ""
        
        if [[ "${URL_K8S_CONFIG}" != "none" ]];then
            download_file "${URL_USER}" "${URL_PASSWORD}" "${HOME}/.kube/config" "${URL_K8S_CONFIG}"
            kubectl config use-context ${_SERVICE_CONTEXT}
        fi

        echo "[-] Kubectl config current-contenxt information: "
        kubectl config current-context
    fi

    echo ""
}

function compare_main_and_non_main_branch()
{
    # CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"

    # If current_branch is not main/master
    # We compare between master/main and this branch
    if [[ "${CURRENT_BRANCH}" != "${MAIN_BRANCH}" ]];then
        echo "[+] Compare branch: ${MAIN_BRANCH}...${CURRENT_BRANCH}"

        git diff --diff-filter=ACMRTUXB --name-only ${MAIN_BRANCH}...${CURRENT_BRANCH} | grep -i "^environments" | grep -i "yaml$" > ${TMPFILE_LISTFILES_COMPARE}

        git diff --diff-filter=ACMRTUXB --name-only ${BRANCH_MAIN}...${BRANCH_CURRENT} | grep -i "^environments" | grep -i "yml$" >> ${TMPFILE_LISTFILES_COMPARE}

        # Check directory have delete.lock, ignore deleted files
        git diff --diff-filter=ACMRTUXB --name-only ${MAIN_BRANCH}...${CURRENT_BRANCH} | grep -i "^environments" | grep -i "\/delete.lock$" > ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock

        echo "[+] FYI, list directories contain delete.lock: "
        cat ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock
        sed -i -e 's/delete.lock/helm.yaml/g' ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock
        cat ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock >> ${TMPFILE_LISTFILES_COMPARE}
        rm -f ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock

    elif [[ "${CURRENT_BRANCH}" == "${MAIN_BRANCH}" ]];then
        # If this branch is : main
        # We compare two latest commits changed files
        LATEST_COMMIT_HASH=$(git log --pretty=format:'%H' -n 2 | head -n 1)
        PREVIOUS_COMMIT_HASH=$(git log --pretty=format:'%H' -n 2 | tail -n 1)

        git diff --diff-filter=ACMRTUXB --name-only HEAD~1...HEAD | grep "^environments" | grep -i "yaml$" > ${TMPFILE_LISTFILES_COMPARE}

        git diff --diff-filter=ACMRTUXB --name-only HEAD~1...HEAD | grep -i "^environments" | grep -i "yml$" >> ${TMPFILE_LISTFILES_COMPARE}
        # Check directory have delete.lock
        git diff --diff-filter=ACMRTUXB --name-only HEAD~1...HEAD | grep -i "^environments" | grep -i "\/delete.lock$" > ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock

        echo "[+] FYI, list directories contain delete.lock: "
        cat ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock
        sed -i -e 's/delete.lock/helm.yaml/g' ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock
        cat ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock >> ${TMPFILE_LISTFILES_COMPARE}
        rm -f ${TMPFILE_LISTFILES_COMPARE}.file-delete-lock
    fi
}

function get_all_list_defined_yaml(){
    # Get all list defined yaml for secrets/configmap
    echo ""
    echo "-------------------------------------------------"
    echo "|   SECRETS KUBERNETES APPLICATION MANAGEMENT   |"
    echo "-------------------------------------------------"
    echo "[*] List file <filename>.yaml is found :"
    compare_main_and_non_main_branch

    if [[ "$(cat ${TMPFILE_LISTFILES_COMPARE} | grep -v "^$" | wc -l | tr -d ' ')" -gt 0 ]];then
        if [[ "${CURRENT_BRANCH}" == "${MAIN_BRANCH}" ]];then
            echo "[+] We find out some changed files between commits branch [main] : ${PREVIOUS_COMMIT_HASH}...${LATEST_COMMIT_HASH}"
        elif [[ "${CURRENT_BRANCH}" != "${MAIN_BRANCH}" ]];then
            echo "[+] We find out some changed files between branches : ${MAIN_BRANCH}...${CURRENT_BRANCH}"
        fi
        cat ${TMPFILE_LISTFILES_COMPARE} | sort | uniq > ${TMPFILE_LIST_YAML}

    else
        if [[ "${CURRENT_BRANCH}" == "${MAIN_BRANCH}" ]];then
            echo "[+] We do not find out any changed files between commits branch [main] : ${PREVIOUS_COMMIT_HASH}...${LATEST_COMMIT_HASH}"
        elif [[ "${CURRENT_BRANCH}" != "${MAIN_BRANCH}" ]];then
            echo "[+] We do not find out any changed files between branches : ${MAIN_BRANCH}...${CURRENT_BRANCH}"
        fi

        if [[ "${SCAN_ALL_FILES}" == "true" ]];then
            echo "[+] We found setting: SCAN_ALL_FILES != true"
            echo "[+] So we decide to scan all files yaml"
            find environments -type f -iname "*.yaml" -o -iname "*.yml" > ${TMPFILE_LIST_YAML}
        else
            echo "[+] We found setting: SCAN_ALL_FILES != true"
            echo "[+] We stop scan all files.yaml"
        fi
    fi

    cat ${TMPFILE_LIST_YAML}
}

function get_unique_list_providers(){
    echo ""
    # Get unique list providers
    cat ${TMPFILE_LIST_YAML} | awk -F'/' '{print $1 "/" $2 "/" $3 "/" $4}' | sort | uniq > ${TMPFILE_LIST_PROVIDERS}
}

function build_k8s_apply_config(){
    # Process each cloud provider service
    while read line
    do
        # Get information
        SERVICE_METADATA_CONFIG="${line}/metadata.conf"
        SERVICE_PROVIDER=$(cat ${SERVICE_METADATA_CONFIG} | grep -i "service_provider" | awk -F':' '{print $2}' | tr -d ' ')
        SERVICE_TYPE=$(cat ${SERVICE_METADATA_CONFIG} | grep -i "service_type" | awk -F':' '{print $2}' | tr -d ' ')
        SERVICE_IDENTIFIER=$(cat ${SERVICE_METADATA_CONFIG} | grep -i "service_identifier" | awk -F':' '{print $2}' | tr -d ' ')
        SERVICE_CONTEXT=$(cat ${SERVICE_METADATA_CONFIG} | grep -i "service_context" | awk -F':' '{print $2}' | tr -d ' ')
        SERVICE_ENVIRONMENT=$(cat ${SERVICE_METADATA_CONFIG} | grep -i "environment" | awk -F':' '{print $2}' | tr -d ' ')

        echo ""
        echo "**"
        echo "** $SERVICE_IDENTIFIER **"
        echo "**"
        echo "Processing on this Kubernetes cluster :"
        echo "+ SERVICE_PROVIDER: $SERVICE_PROVIDER"
        echo "+ SERVICE_TYPE: $SERVICE_TYPE"
        echo "+ SERVICE_IDENTIFIDER: $SERVICE_IDENTIFIER"
        echo "+ SERVICE_CONTEXT: ${SERVICE_CONTEXT}"
        echo "+ SERVICE_ENVIRONMENT: ${SERVICE_ENVIRONMENT}"
        echo " "

        function k8s_config_auth() {
            # We need a way to authenticate Kubernetes API
            kubernetes_auth_login ${SERVICE_PROVIDER} ${SERVICE_TYPE} ${SERVICE_IDENTIFIER} ${SERVICE_CONTEXT} ${SERVICE_ENVIRONMENT}
        }

        k8s_config_auth

        # Get list directory contains file .yaml
        cat /dev/null > ${TMPFILE_LIST_YAML_DIRS}
        for file in `cat ${TMPFILE_LIST_YAML} | grep -i "${line}"`
        do
            dirname $file >> ${TMPFILE_LIST_YAML_DIRS}
        done

        cat ${TMPFILE_LIST_YAML_DIRS} | grep -v "^$" | sort | uniq > ${TMPFILE_LIST_YAML_DIRS}.tmp
        cat ${TMPFILE_LIST_YAML_DIRS}.tmp > ${TMPFILE_LIST_YAML_DIRS}
        
        if [[ -f ${TMPFILE_LIST_YAML_DIRS}.tmp ]];then
            rm -f ${TMPFILE_LIST_YAML_DIRS}.tmp
        fi

        # Process kubectl apply/replace from each directory
        while read directory
        do
            echo "[+] Apply & replace secrets/configmap in this directory: ${directory}"
            SERVICE_NAME=$(echo $directory | awk -F/ '{print $NF}' | tr -d ' ')
            PATH_FILE=$(ls -d "$directory"/* | head -n1)
            NAMESPACE=$(cat ${PATH_FILE} | grep -i "namespace" | awk -F':' '{print $2}' | head -n1 | tr -d ' ')
            POD_NAME=$(kubectl get pods -n ${NAMESPACE} -l="nameRelease=${SERVICE_NAME}" -o=name | sed "s/^.\{4\}//")
            if [[ ${POD_NAME} == "null" ]];then
                POD_NAME=$(kubectl get pods -n $NAMESPACE -o=name | grep $SERVICE_NAME | sed "s/^.\{4\}//")
            fi
            
            echo "We are running on namespace: $NAMESPACE"

            function k8s_apply_config() {
                # Apply kubectl
                kubectl apply -f ${directory}
                # Replace kubectl, save time, we comment this command
                kubectl replace -f ${directory}
                
                local POD_RESTART="true"

                if [[ ${RESTART_NS_BLACKLIST} != none ]];then
                    for ns in ${RESTART_NS_BLACKLIST[@]}; do
                        if [[ "${NAMESPACE}" == ${ns} ]];then
                            POD_RESTART="false"
                        fi
                    done
                fi

                # Restart deploys
                if [[ ${POD_RESTART} == "true" ]];then

                    POD_KIND=$(kubectl get pod ${POD_NAME} -n ${NAMESPACE} -o jsonpath='{.metadata.ownerReferences[0].kind}')
                    DEPLOY_NAME=$(kubectl get pod ${POD_NAME} -n ${NAMESPACE} -o jsonpath='{.metadata.ownerReferences[0].name}')

                    if [[ ${DEPLOY_NAME} == "" ]];then
                        DEPLOY_NAME="${SERVICE_NAME}"
                    fi

                    kubectl rollout restart ${POD_KIND} -n ${NAMESPACE} ${DEPLOY_NAME}
                fi
                
            }
            
            k8s_apply_config

            function reconnect() {
                RAMDOM_NUM=$((30 + $RANDOM % 90))
                echo "Server can't connect, we will waiting ${RAMDOM_NUM}s and auto try again."
                sleep ${RAMDOM_NUM}
                # We will remove old config k8s
                [ -d "$HOME/.kube" ] && rm -rf "$HOME/.kube" || echo "Folder is not exists !"
                # Recreate config k8s and apply env
                k8s_config_auth
                k8s_apply_config
            }

            until $(kubectl cluster-info &>/dev/null)
            do
                reconnect
            done
            echo "[+] Done"
            echo ""

        done < ${TMPFILE_LIST_YAML_DIRS}

    done < ${TMPFILE_LIST_PROVIDERS}
}

################
#   Main flow  #
################

###### START
function main(){
    # Action based on ${ACTION} arg
    case ${ACTION} in
    "-v" | "--version")
        about
        ;;
    "-h" | "--help")
        help
        ;;
    *)
        ### Init tempfile, call function init()
        init

        ### Checking supported tool & plugin on local machine
        pre_check_dependencies "kubectl"

        ### Pre-checking
        pre_checking
        
        get_all_list_defined_yaml

        get_unique_list_providers

        build_k8s_apply_config
        ;;
    esac

    # Clean trash of service
    cleanup
}

main "${@}"

exit 0