curl -X POST http://localhost:8000/api/dns/push \
  -H "Content-Type: application/json" \
  -d @json/dnsproof.org.json
  
curl -X GET http://localhost:8000/api/dnssec/status/dnsproof.org 

curl -X POST http://localhost:8000/api/dnssec/enable/dnsproof.org 

curl -X POST http://localhost:8000/api/dnssec/disable/dnsproof.org 

curl -X POST http://localhost:8000/api/dnssec/auto_resign/off

curl -X POST http://localhost:8000/api/dnssec/auto_resign/on

curl -X POST http://localhost:8000/api/dnssec/rotate/zsk/dnsproof.org

curl -X POST http://localhost:8000/api/dnssec/rotate/dnsproof.org

curl -X GET http://localhost:8000/api/dns/verify-ns/dnsproof.org