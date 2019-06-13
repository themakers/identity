Identity Mongo DB backend Impl
==============================


```bash
mongod --smallfiles --bind_ip_all --replSet rs0 --dbpath=$HOME/mongodb

mongo> rs.initiate({_id: "rs0", members: [{_id: 0, host: "127.0.0.1:27017"}] })
mongo> db.adminCommand( { setFeatureCompatibilityVersion: "4.0" } )
```
