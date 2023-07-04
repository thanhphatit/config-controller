# POD_NAME=$(kubectl get pods -n monitoring -o=name | grep prometheus | sed "s/^.\{4\}//")
pod_name=$(kubectl get pod -n monitoring -o jsonpath='{.items[0].metadata.name}') | grep prometheus
#POD_KIND=$(kubectl get pod ${POD_NAME} -n ${NAMESPACE} -o jsonpath='{.metadata.ownerReferences[0].kind}')
echo "${pod_name}"