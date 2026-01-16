curl -X POST http://localhost:8000/api/dns/push \
  -H "Content-Type: application/json" \
  -d @app/json/dnsproof.org.json
  
# Internal use
curl -X GET http://localhost:8000/api/dnssec/status-nameserver/dnsproof.org 

curl -X POST http://localhost:8000/api/dnssec/enable/dnsproof.org 

curl -X POST http://localhost:8000/api/dnssec/disable/dnsproof.org 

curl -X POST http://localhost:8000/api/dnssec/auto_resign/off

curl -X POST http://localhost:8000/api/dnssec/auto_resign/on

curl -X POST http://localhost:8000/api/dnssec/rotate/zsk/dnsproof.org

curl -X POST http://localhost:8000/api/dnssec/rotate/dnsproof.org

curl -X GET http://localhost:8000/api/dnssec/status/dnsproof.org


# nameserver
curl -X GET http://localhost:8000/api/ns/verify-ns/dnsproof.org

curl -X GET http://localhost:8000/api/ns/ns_propagation_status/dnsproof.org

# DNS management
# add
curl -X POST http://localhost:8000/api/dns/records \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "dnsproof.org",
    "record": {
      "type": "TXT",
      "name": "@",
      "value": "test-adding",
      "ttl": 3600
    }
  }'

# edit
curl -X PUT "http://localhost:8000/api/dns/records/8e41158f02120df39a77c4328489c60d64ced88045fa1df0289577e6f4f9fb20" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "dnsproof.org",
    "record": {
      "type": "TXT",
      "name": "@",
      "value": "test-edited",
      "ttl": 3600
    }
  }'

# delete
curl -X DELETE "http://localhost:8000/api/dns/records/3ea200f692b42835a2492f36e6df9958f010825d3732ab642f5236da41e19354?domain=dnsproof.org" \
  -H "Content-Type: application/json" 