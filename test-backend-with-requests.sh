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
    "records": [{
      "type": "TXT",
      "name": "@",
      "value": "test-adding1",
      "ttl": 3600
    },
    {
      "type": "TXT",
      "name": "@",
      "value": "test-adding2",
      "ttl": 3600
    }]
  }'

# edit
curl -X PUT "http://localhost:8000/api/dns/records" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "dnsproof.org",
    "edits" :[
      {
        "record_id": "b1a81447340f4832c7b3fe7438c78ee9c8b8f7baa2587441acefbe61cd9a8d19",
        "record": {
          "type": "TXT",
          "name": "@",
          "value": "test-edited1",
          "ttl": 3600
        }
      },
      {
        "record_id": "0e1ed1ba1747caa4ec36ff1393b8c18ae6b01288e1e9e0f8d0257cbe37af8f58",
        "record": {
          "type": "TXT",
          "name": "@",
          "value": "test-edited2",
          "ttl": 3600
        }
      }
    ]
  }'

# delete
curl -X DELETE http://localhost:8000/api/dns/records \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "dnsproof.org",
    "record_ids": [
      "64b0867248ea31875a44468acc755af15d9dc1049f9284f21a91c375bcc670ca",
      "8e5af955f49712d9a4a26925be3082be15fc41243b01aa3084ac0ec44c80b2bb"
    ]
  }'
