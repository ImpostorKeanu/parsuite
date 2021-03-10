# Example Command

This command would ingest the records in `weblogic.csv` and apply the updates
to the records hosted in the Neo4J server referenced by `--bolt-uri`.

```
parsuite bloodhound_property_manager_neo4j -ifs weblogic.csv --bolt-uri bolt://192.168.1.5:7687 --username neo4j --password password
```

The CSV file may contain something like the following:

```csv
node_type,query_property_name,query_property_value,update_property_name,update_property_value
User,name,USER@SOMEDOMAIN.COM,owned,true
```

# CSV File Format Notes

## Raw Header

```
node_type,query_property_name,query_property_value,update_property_name,update_property_value
```

## Explanation

|Field Name|Description|Notes|
|---|---|---|
|`node_type`|Indicates the type of node that will be queried from the Neo4j database.| Possible values (**CASE SENSITIVE**):<br><br>Computer, Domain, GPO, Group, OU, User|
|`query_property_name`|The property on the `node_type` that that will be queried.|For instance, you may want to look up `User` by `name`, so the value for this field would be `name`.|
|`query_property_value`|The value that will be searched against the `query_property_name` value.|If you wanted to updated a user with the name `USER@SOMEDOMAIN.COM`, then that would be the value of one record here.|
|`update_property_name`|The name of the property to be updated on the value returned from the query described by `query_property_name` and `query_property_value`.|If you wanted to set `USER@SOMEDOMAIN.COM` as owned, then you would supply the `owned` value to this field.|
|`update_property_value`|The value that will be set for this field on the target node.|If you wanted to set the `owned` property of `USER@SOMEDOMAIN.COM` to true, you would set this field to `true`.|

## Example

### Objective

We want to set `USER@SOMEDOMAIN.COM` to be shown as "owned" in BloodHound.

### CSV File

```csv
node_type,query_property_name,query_property_value,update_property_name,update_property_value
User,name,USER@SOMEDOMAIN.COM,owned,true
```
