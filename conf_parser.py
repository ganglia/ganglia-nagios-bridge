#! /usr/bin/python

from configobj import ConfigObj,ConfigObjError


class ConfigParser:
    def __init__(self):
        self.clusters =[]

    def parse (self,config_file):
        try:
            config = ConfigObj(config_file)

            #get gmetad host information and nagios checkresult directory
            self.gmetad_host = config.pop('gmetad_host')
            self.gmetad_port = config.pop('gmetad_port')
            self.force_dmax = config.pop('force_dmax')
            self.tmax_grace = config.pop('tmax_grace')
            self.strip_domains = config.pop('strip_domains')
            self.nagios_result_dir = config.pop('nagios_result_dir')


            for cluster_name in config.keys():
                cluster_hosts = {}
                #get hosts in the cluster
                for host_name in config[cluster_name].keys():
                    metrics = []
                    #collect metric for each host in the cluster
                    for metric_name in config[cluster_name][host_name].keys():
                        metric_def = {}
                        metric_def['service_name'] = config[cluster_name][host_name][metric_name]['service_name']
                        if 'crit_above' in config[cluster_name][host_name][metric_name].keys():
                            metric_def['crit_above'] = config[cluster_name][host_name][metric_name]['crit_above']
                            metric_def['crit_below'] = None
                        if 'crit_below' in config[cluster_name][host_name][metric_name].keys():
                            metric_def['crit_below'] = config[cluster_name][host_name][metric_name]['crit_below']
                            metric_def['crit_above'] = None
                        if 'warn_above' in config[cluster_name][host_name][metric_name].keys():
                            metric_def['warn_above'] = config[cluster_name][host_name][metric_name]['warn_above']
                            metric_def['warn_below'] = None
                        if 'warn_below' in config[cluster_name][host_name][metric_name].keys():
                            metric_def['warn_below'] = config[cluster_name][host_name][metric_name]['warn_below']
                            metric_def['warn_above'] = None
                        metrics.append((metric_name,metric_def))
                    for host in host_name.split(','):
                        cluster_hosts.setdefault(host.lstrip(), []).append(metrics)
                self.clusters.append((cluster_name,cluster_hosts))

        except (ConfigObjError, IOError), e:
            print 'Could not read  %s' % (e)
