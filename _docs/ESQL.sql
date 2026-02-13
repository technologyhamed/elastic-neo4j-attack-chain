FROM .alerts-security.alerts-*
| WHERE @timestamp > now() - 7 days
| KEEP
    @timestamp,
    kibana.alert.rule.name,
    kibana.alert.severity,
    event.category,
    host.name,
    process.name,
    user.name,
    kibana.alert.ancestors.id
| SORT kibana.alert.ancestors.id, @timestamp


FROM .alerts-security.alerts-*
| WHERE @timestamp > now() - 7 days
| STATS
    alert_count = COUNT(*)
  BY kibana.alert.ancestors.id
| SORT alert_count DESC


FROM .alerts-security.alerts-*
| WHERE @timestamp > now() - 7 days
| STATS
    alert_count = COUNT(*),
    rules = VALUES(kibana.alert.rule.name),
    severities = VALUES(kibana.alert.severity),
    hosts = VALUES(host.name)
  BY kibana.alert.ancestors.id
| SORT alert_count DESC


FROM .alerts-security.alerts-*
| WHERE @timestamp > now() - 7 days
| STATS chain_count = COUNT_DISTINCT(kibana.alert.ancestors.id)






FROM .alerts-security.alerts-*
| MV_EXPAND kibana.alert.ancestors.id
| WHERE kibana.alert.ancestors.depth >= 0
| EVAL
    chain_id = kibana.alert.ancestors.id,
    node_depth = kibana.alert.ancestors.depth,
    tactic_id = kibana.alert.rule.threat.tactic.id,
    tactic_name = kibana.alert.rule.threat.tactic.name
| STATS
    
BY chain_id ,tactic_name,tactic_id
| KEEP chain_id,tactic_name,tactic_id
| SORT chain_id


FROM .alerts-security.alerts-*
| MV_EXPAND kibana.alert.ancestors.id
| MV_EXPAND kibana.alert.rule.threat.tactic.id
| MV_EXPAND kibana.alert.rule.threat.technique.id
| SORT @timestamp
| STATS
    alert_count = COUNT(),
    parent_tactics = VALUES(kibana.alert.rule.threat.tactic.id),
    parent_tactic_names = VALUES(kibana.alert.rule.threat.tactic.name),
    parent_techniques = VALUES(kibana.alert.rule.threat.technique.id),
    parent_technique_names = VALUES(kibana.alert.rule.threat.technique.name),
    src_port = VALUES(source.port),
    first_seen = MIN(@timestamp),
    last_seen  = MAX(@timestamp)
  BY kibana.alert.ancestors.id
| KEEP kibana.alert.ancestors.id, alert_count,parent_techniques,src_port
| SORT kibana.alert.ancestors.id 


FROM .alerts-security.alerts-*
| MV_EXPAND kibana.alert.ancestors.id
| MV_EXPAND kibana.alert.rule.threat.tactic.id
| MV_EXPAND kibana.alert.rule.threat.technique.id
| SORT @timestamp
| STATS
    alert_count = COUNT(),
    parent_tactics = VALUES(kibana.alert.rule.threat.tactic.id),
    parent_tactic_names = VALUES(kibana.alert.rule.threat.tactic.name),
    parent_techniques = VALUES(kibana.alert.rule.threat.technique.id),
    parent_technique_names = VALUES(kibana.alert.rule.threat.technique.name),
    src_port = VALUES(source.port),
    first_seen = MIN(@timestamp),
    last_seen  = MAX(@timestamp)
  BY kibana.alert.ancestors.id
| KEEP kibana.alert.ancestors.id, alert_count,parent_techniques,src_port
| SORT kibana.alert.ancestors.id 
