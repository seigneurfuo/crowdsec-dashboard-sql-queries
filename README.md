# Crowdsec's Dashboard - Metabase Requests / Requètes Metabase pour Crowdsec Dashboard

- [EN] List of Crowdsec queries used by Crowdsec Dashboard (via Metabase)
- [FR] Liste des requètes Crowdsec utilisées par Crowdsec Dashboard (via Metabase)

## Sources

- https://raw.githubusercontent.com/crowdsecurity/example-docker-compose/refs/heads/main/basic/crowdsec/dashboard/Dockerfile

## Requests / Requètes

### Actives Decisions List

```sql
SELECT "decisions"."alert_decisions" AS "Alert ID", "decisions"."origin" AS "Origin", "decisions"."value" as "Value", "decisions"."scope" as "Scope", "decisions"."type" as "Type", "decisions"."scenario" as "Scenario", datetime(strftime('%Y-%m-%d %H:%M:%S',"decisions"."until")) AS "Until", (SELECT "alerts"."source_country" FROM "alerts" WHERE "alerts"."id" = "decisions"."id") AS "Country", (SELECT "alerts"."source_as_name" FROM "alerts" WHERE "alerts"."id" = "decisions"."id") AS "AS" 
FROM "decisions"
WHERE datetime(strftime('%Y-%m-%d %H:%M:%S',"decisions"."until")) > datetime('now') 
group BY scope, value, simulated, type
ORDER BY created_at DESC
```



### Alerts History

```sql
SELECT "alerts"."id" AS "id", datetime(strftime('%Y-%m-%d %H:%M:%S',"alerts"."created_at")) AS "Date", "alerts"."scenario" AS "Reason", "alerts"."source_scope" AS "Scope", "alerts"."source_value" AS "Value", "alerts"."source_country" AS "Country", "alerts"."source_as_name" AS "AS", datetime(strftime('%Y-%m-%d %H:%M:%S', "alerts"."started_at")) AS "Started", datetime(strftime('%Y-%m-%d %H:%M:%S', "alerts"."stopped_at")) AS "Stopped", "alerts"."message" AS "Message", "alerts"."simulated" AS "Simulation", "Decisions"."origin" AS "Origin", "Machines"."machine_id" AS "Machine"
FROM "alerts"
LEFT JOIN "decisions" "Decisions" ON "alerts"."id" = "Decisions"."alert_decisions"
LEFT JOIN "machines" "Machines" ON "alerts"."machine_alerts" = "Machines"."id"
[[WHERE "Machines"."machine_id" = {{machine}}]]
GROUP BY alerts.created_at
ORDER BY datetime(strftime('%Y-%m-%d %H:%M:%S',"alerts"."created_at")) desc
```



### By AS

```sql
SELECT
  "alerts"."source_as_name" AS "source_as_name",
  COUNT(*) AS "count"
FROM
  "alerts"
 
LEFT JOIN (
    SELECT
      "decisions"."id" AS "id",
      "decisions"."created_at" AS "created_at",
      "decisions"."updated_at" AS "updated_at",
      "decisions"."until" AS "until",
      "decisions"."scenario" AS "scenario",
      "decisions"."type" AS "type",
      "decisions"."start_ip" AS "start_ip",
      "decisions"."end_ip" AS "end_ip",
      "decisions"."start_suffix" AS "start_suffix",
      "decisions"."end_suffix" AS "end_suffix",
      "decisions"."ip_size" AS "ip_size",
      "decisions"."scope" AS "scope",
      "decisions"."value" AS "value",
      "decisions"."origin" AS "origin",
      "decisions"."simulated" AS "simulated",
      "decisions"."uuid" AS "uuid",
      "decisions"."alert_decisions" AS "alert_decisions"
    FROM
      "decisions"
  ) AS "Decisions" ON "alerts"."id" = "Decisions"."alert_decisions"
WHERE
  ("Decisions"."origin" <> 'CAPI')
 
    OR ("Decisions"."origin" IS NULL)
GROUP BY
  "alerts"."source_as_name"
ORDER BY
  "count" DESC,
  "alerts"."source_as_name" ASC
```



### By Machine

```sql
SELECT
  "machines__via__machine_alerts"."machine_id" AS "machines__via__machine_alerts__machine_id",
  count(distinct "alerts"."id") AS "count"
FROM
  "alerts"
 
LEFT JOIN (
    SELECT
      "decisions"."id" AS "id",
      "decisions"."created_at" AS "created_at",
      "decisions"."updated_at" AS "updated_at",
      "decisions"."until" AS "until",
      "decisions"."scenario" AS "scenario",
      "decisions"."type" AS "type",
      "decisions"."start_ip" AS "start_ip",
      "decisions"."end_ip" AS "end_ip",
      "decisions"."start_suffix" AS "start_suffix",
      "decisions"."end_suffix" AS "end_suffix",
      "decisions"."ip_size" AS "ip_size",
      "decisions"."scope" AS "scope",
      "decisions"."value" AS "value",
      "decisions"."origin" AS "origin",
      "decisions"."simulated" AS "simulated",
      "decisions"."uuid" AS "uuid",
      "decisions"."alert_decisions" AS "alert_decisions"
    FROM
      "decisions"
  ) AS "Decisions" ON "alerts"."id" = "Decisions"."alert_decisions"
  LEFT JOIN "machines" AS "machines__via__machine_alerts" ON "alerts"."machine_alerts" = "machines__via__machine_alerts"."id"
WHERE
  (
    "machines__via__machine_alerts"."machine_id" IS NOT NULL
  )
 
   AND (
    ("machines__via__machine_alerts"."machine_id" <> '')
   
    OR (
      "machines__via__machine_alerts"."machine_id" IS NULL
    )
  )
GROUP BY
  "machines__via__machine_alerts"."machine_id"
ORDER BY
  "machines__via__machine_alerts"."machine_id" ASC
```



### By Origin

```sql
SELECT
  "Decisions"."origin" AS "Decisions__origin",
  COUNT(*) AS "count"
FROM
  "alerts"
 
LEFT JOIN (
    SELECT
      "decisions"."id" AS "id",
      "decisions"."created_at" AS "created_at",
      "decisions"."updated_at" AS "updated_at",
      "decisions"."until" AS "until",
      "decisions"."scenario" AS "scenario",
      "decisions"."type" AS "type",
      "decisions"."start_ip" AS "start_ip",
      "decisions"."end_ip" AS "end_ip",
      "decisions"."start_suffix" AS "start_suffix",
      "decisions"."end_suffix" AS "end_suffix",
      "decisions"."ip_size" AS "ip_size",
      "decisions"."scope" AS "scope",
      "decisions"."value" AS "value",
      "decisions"."origin" AS "origin",
      "decisions"."simulated" AS "simulated",
      "decisions"."uuid" AS "uuid",
      "decisions"."alert_decisions" AS "alert_decisions"
    FROM
      "decisions"
  ) AS "Decisions" ON "alerts"."id" = "Decisions"."alert_decisions"
GROUP BY
  "Decisions"."origin"
ORDER BY
  "Decisions"."origin" ASC
```



### By Scenario

```sql
SELECT
  "alerts"."scenario" AS "scenario",
  COUNT(*) AS "count"
FROM
  "alerts"
 
LEFT JOIN (
    SELECT
      "decisions"."id" AS "id",
      "decisions"."created_at" AS "created_at",
      "decisions"."updated_at" AS "updated_at",
      "decisions"."until" AS "until",
      "decisions"."scenario" AS "scenario",
      "decisions"."type" AS "type",
      "decisions"."start_ip" AS "start_ip",
      "decisions"."end_ip" AS "end_ip",
      "decisions"."start_suffix" AS "start_suffix",
      "decisions"."end_suffix" AS "end_suffix",
      "decisions"."ip_size" AS "ip_size",
      "decisions"."scope" AS "scope",
      "decisions"."value" AS "value",
      "decisions"."origin" AS "origin",
      "decisions"."simulated" AS "simulated",
      "decisions"."uuid" AS "uuid",
      "decisions"."alert_decisions" AS "alert_decisions"
    FROM
      "decisions"
  ) AS "Decisions" ON "alerts"."id" = "Decisions"."alert_decisions"
WHERE
  ("Decisions"."origin" <> 'CAPI')
 
    OR ("Decisions"."origin" IS NULL)
GROUP BY
  "alerts"."scenario"
ORDER BY
  "alerts"."scenario" ASC
```



### By Source IP

```sql
SELECT
  "alerts"."source_value" AS "source_value",
  COUNT(*) AS "count"
FROM
  "alerts"
 
LEFT JOIN (
    SELECT
      "decisions"."id" AS "id",
      "decisions"."created_at" AS "created_at",
      "decisions"."updated_at" AS "updated_at",
      "decisions"."until" AS "until",
      "decisions"."scenario" AS "scenario",
      "decisions"."type" AS "type",
      "decisions"."start_ip" AS "start_ip",
      "decisions"."end_ip" AS "end_ip",
      "decisions"."start_suffix" AS "start_suffix",
      "decisions"."end_suffix" AS "end_suffix",
      "decisions"."ip_size" AS "ip_size",
      "decisions"."scope" AS "scope",
      "decisions"."value" AS "value",Actives Decisions List
      "decisions"."origin" AS "origin",
      "decisions"."simulated" AS "simulated",
      "decisions"."uuid" AS "uuid",
      "decisions"."alert_decisions" AS "alert_decisions"
    FROM
      "decisions"
  ) AS "Decisions" ON "alerts"."id" = "Decisions"."alert_decisions"
WHERE
  LOWER("alerts"."source_scope") LIKE '%ip%'
GROUP BY
  "alerts"."source_value"
ORDER BY
  "count" DESC,
  "alerts"."source_value" ASC
```



### Machines Timeline

```sql
SELECT
  DATETIME(STRFTIME('%Y-%m-%d %H:00', "alerts"."stopped_at")) AS "stopped_at",
  "machines__via__machine_alerts"."machine_id" AS "machines__via__machine_alerts__machine_id",
  count(distinct "alerts"."id") AS "count"
FROM
  "alerts"
 
LEFT JOIN (
    SELECT
      "decisions"."id" AS "id",
      "decisions"."created_at" AS "created_at",
      "decisions"."updated_at" AS "updated_at",
      "decisions"."until" AS "until",
      "decisions"."scenario" AS "scenario",
      "decisions"."type" AS "type",
      "decisions"."start_ip" AS "start_ip",
      "decisions"."end_ip" AS "end_ip",
      "decisions"."start_suffix" AS "start_suffix",
      "decisions"."end_suffix" AS "end_suffix",
      "decisions"."ip_size" AS "ip_size",
      "decisions"."scope" AS "scope",
      "decisions"."value" AS "value",
      "decisions"."origin" AS "origin",
      "decisions"."simulated" AS "simulated",
      "decisions"."uuid" AS "uuid",
      "decisions"."alert_decisions" AS "alert_decisions"
    FROM
      "decisions"
  ) AS "Decisions" ON "alerts"."id" = "Decisions"."alert_decisions"
  LEFT JOIN "machines" AS "machines__via__machine_alerts" ON "alerts"."machine_alerts" = "machines__via__machine_alerts"."id"
WHERE
  ("Decisions"."origin" <> 'CAPI')
 
    OR ("Decisions"."origin" IS NULL)
GROUP BY
  DATETIME(STRFTIME('%Y-%m-%d %H:00', "alerts"."stopped_at")),
  "machines__via__machine_alerts"."machine_id"
ORDER BY
  DATETIME(STRFTIME('%Y-%m-%d %H:00', "alerts"."stopped_at")) ASC,
  "machines__via__machine_alerts"."machine_id" ASC
```



### Map

```sql
SELECT
  "alerts"."source_country" AS "source_country",
  count(distinct "alerts"."id") AS "count"
FROM
  "alerts"
 
LEFT JOIN (
    SELECT
      "decisions"."id" AS "id",
      "decisions"."created_at" AS "created_at",
      "decisions"."updated_at" AS "updated_at",
      "decisions"."until" AS "until",
      "decisions"."scenario" AS "scenario",
      "decisions"."type" AS "type",
      "decisions"."start_ip" AS "start_ip",
      "decisions"."end_ip" AS "end_ip",
      "decisions"."start_suffix" AS "start_suffix",
      "decisions"."end_suffix" AS "end_suffix",
      "decisions"."ip_size" AS "ip_size",
      "decisions"."scope" AS "scope",
      "decisions"."value" AS "value",
      "decisions"."origin" AS "origin",
      "decisions"."simulated" AS "simulated",
      "decisions"."uuid" AS "uuid",
      "decisions"."alert_decisions" AS "alert_decisions"
    FROM
      "decisions"
  ) AS "Decisions" ON "alerts"."id" = "Decisions"."alert_decisions"
WHERE
  ("Decisions"."origin" <> 'CAPI')
 
    OR ("Decisions"."origin" IS NULL)
GROUP BY
  "alerts"."source_country"
ORDER BY
  "alerts"."source_country" ASC
```



### Scenarios Timeline

```sql
SELECT
  DATETIME(STRFTIME('%Y-%m-%d %H:00', "alerts"."stopped_at")) AS "stopped_at",
  "alerts"."scenario" AS "scenario",
  count(distinct "alerts"."id") AS "count"
FROM
  "alerts"
 
LEFT JOIN (
    SELECT
      "decisions"."id" AS "id",
      "decisions"."created_at" AS "created_at",
      "decisions"."updated_at" AS "updated_at",
      "decisions"."until" AS "until",
      "decisions"."scenario" AS "scenario",
      "decisions"."type" AS "type",
      "decisions"."start_ip" AS "start_ip",
      "decisions"."end_ip" AS "end_ip",
      "decisions"."start_suffix" AS "start_suffix",
      "decisions"."end_suffix" AS "end_suffix",
      "decisions"."ip_size" AS "ip_size",
      "decisions"."scope" AS "scope",
      "decisions"."value" AS "value",
      "decisions"."origin" AS "origin",
      "decisions"."simulated" AS "simulated",
      "decisions"."uuid" AS "uuid",
      "decisions"."alert_decisions" AS "alert_decisions"
    FROM
      "decisions"
  ) AS "Decisions" ON "alerts"."id" = "Decisions"."alert_decisions"
WHERE
  ("Decisions"."origin" <> 'CAPI')
 
    OR ("Decisions"."origin" IS NULL)
GROUP BY
  DATETIME(STRFTIME('%Y-%m-%d %H:00', "alerts"."stopped_at")),
  "alerts"."scenario"
ORDER BY
  DATETIME(STRFTIME('%Y-%m-%d %H:00', "alerts"."stopped_at")) ASC,
  "alerts"."scenario" ASC
```



### Top IPs

```sql
SELECT
  "alerts"."source_value" AS "source_value",
  COUNT(*) AS "count"
FROM
  "alerts"
 
LEFT JOIN (
    SELECT
      "decisions"."id" AS "id",
      "decisions"."created_at" AS "created_at",
      "decisions"."updated_at" AS "updated_at",
      "decisions"."until" AS "until",
      "decisions"."scenario" AS "scenario",
      "decisions"."type" AS "type",
      "decisions"."start_ip" AS "start_ip",
      "decisions"."end_ip" AS "end_ip",
      "decisions"."start_suffix" AS "start_suffix",
      "decisions"."end_suffix" AS "end_suffix",
      "decisions"."ip_size" AS "ip_size",
      "decisions"."scope" AS "scope",
      "decisions"."value" AS "value",
      "decisions"."origin" AS "origin",
      "decisions"."simulated" AS "simulated",
      "decisions"."uuid" AS "uuid",
      "decisions"."alert_decisions" AS "alert_decisions"
    FROM
      "decisions"
  ) AS "Decisions" ON "alerts"."id" = "Decisions"."alert_decisions"
WHERE
  ("Decisions"."origin" <> 'CAPI')
 
    OR ("Decisions"."origin" IS NULL)
GROUP BY
  "alerts"."source_value"
ORDER BY
  "count" DESC,
  "alerts"."source_value" ASC
```



### Total Active Decisions

```sql
SELECT count(distinct(simulated||value||scope||type)) from decisions WHERE datetime(strftime('%Y-%m-%d %H:%M:%S',"decisions"."until")) > datetime('now');
```



### Total Alerts

```sql
SELECT
  count(distinct "alerts"."id") AS "count"
FROM
  "alerts"
 
LEFT JOIN (
    SELECT
      "decisions"."id" AS "id",
      "decisions"."created_at" AS "created_at",
      "decisions"."updated_at" AS "updated_at",
      "decisions"."until" AS "until",
      "decisions"."scenario" AS "scenario",
      "decisions"."type" AS "type",
      "decisions"."start_ip" AS "start_ip",
      "decisions"."end_ip" AS "end_ip",
      "decisions"."start_suffix" AS "start_suffix",
      "decisions"."end_suffix" AS "end_suffix",
      "decisions"."ip_size" AS "ip_size",
      "decisions"."scope" AS "scope",
      "decisions"."value" AS "value",
      "decisions"."origin" AS "origin",
      "decisions"."simulated" AS "simulated",
      "decisions"."uuid" AS "uuid",
      "decisions"."alert_decisions" AS "alert_decisions"
    FROM
      "decisions"
  ) AS "Decisions" ON "alerts"."id" = "Decisions"."alert_decisions"
```



### Total Bouncers

```sql
SELECT
  COUNT(*) AS "count"
FROM
  "bouncers"
```



### Total Machines

```sql
SELECT
  COUNT(*) AS "count"
FROM
  "machines"
```









