Identity Mongo DB backend Impl
==============================


```bash
mongod --smallfiles --bind_ip_all --replSet rs0 --dbpath=$HOME/mongodb

mongo> rs.initiate()
mongo> db.adminCommand( { setFeatureCompatibilityVersion: "4.0" } )
```
