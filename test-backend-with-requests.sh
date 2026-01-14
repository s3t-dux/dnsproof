curl -X POST http://localhost:8000/api/dns/push \
  -H "Content-Type: application/json" \
  -d @json/dnsproof.org.json
  
curl -X GET http://localhost:8000/api/dnssec/status/dnsproof.org 

curl -X POST http://localhost:8000/api/dnssec/enable/dnsproof.org 

curl -X POST http://localhost:8000/api/dnssec/disable/dnsproof.org 