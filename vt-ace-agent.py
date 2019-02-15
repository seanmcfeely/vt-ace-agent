#!/usr/bin/env python3
import argparse
import hashlib
import sys
import os
import requests
import time
import json
import pprint
from urllib.parse import urlparse
from configparser import ConfigParser

try:
    from virus_total_apis import PrivateApi
except ImportError:
    raise ImportError('virustotal-api (https://pypi.org/project/virustotal-api/) required')

try:
    import ace_api
except ImportError:
    raise ImportError('ace-api (https://pypi.org/project/ace-api) required')

class TablePrinter(object):
    """Print a list of dicts as a table.

    :param fmt: list of tuple(heading, key, width)
    :param sep: string, separation between columns
    :param ul: string, character to underline column label, or None for no underlining
    :return: A string representation of the table, ready to be printed

    Each tuple in the fmt list of tuples is like so:

    :heading: str, column label
    :key: dictionary key to value to print
    :width: int, column width in chars
    """
    def __init__(self, fmt, sep=' ', ul=None):
        super(TablePrinter,self).__init__()
        self.fmt   = str(sep).join('{lb}{0}:{1}{rb}'.format(key, width, lb='{', rb='}') for heading,key,width in fmt)
        self.head  = {key:heading for heading,key,width in fmt}
        self.ul    = {key:str(ul)*width for heading,key,width in fmt} if ul else None
        self.width = {key:width for heading,key,width in fmt}

    def row(self, data):
        return self.fmt.format(**{ k:str(data.get(k,''))[:w] for k,w in self.width.items() })

    def __call__(self, dataList):
        _r = self.row
        res = [_r(data) for data in dataList]
        res.insert(0, _r(self.head))
        if self.ul:
            res.insert(1, _r(self.ul))
        return '\n'.join(res)

class VT_Resource():

    def __init__(self, resource, config, proxies={}):
        self.resource = resource
        self.origional_resource = resource
        # is our resource a url?
        self.url = None
        parsed_resource = urlparse(resource)
        if parsed_resource.netloc:
            self.url = resource
        # is our resource a file path?
        self.file_path = None
        self.sha256_hash = None
        if os.path.exists(resource):
            self.file_path = resource
            with open(resource, 'rb') as fp:
                self.sha256_hash = hashlib.sha256(fp.read()).hexdigest()
            self.resource = self.sha256_hash
        self.greatest_common_filename = None

        self.vt = PrivateApi(api_key=config['global']['api_key'], proxies=proxies)

        self.url_result = None
        self.file_result = None
        self.result_type = None

    def make_comment(self, comment):
        result = self.vt.put_comments(self.resource, comment)
        return result

    @property
    def results(self):
        """Return any results we have."""
        if self.result_type is 'file':
            return self.file_result['results']
        if self.result_type is 'url':
            return self.url_result['results']
        return None

    @property
    def in_vt(self):
        """Return True if the resource is in the VT dataset."""
        if not self.result_type:
            self.search()
        if self.results['response_code'] == 0:
            return False
        elif self.results['response_code'] == 1:
            return True
        else:
            raise Exception("Unexpected response_code in result")        

    def search(self):
        if self.url:
            self.url_result = self.vt.get_url_report(self.resource)
            self.result_type = 'url'
        else:
            self.file_result = self.vt.get_file_report(self.resource)
            self.result_type = 'file'
        if 'submission_names' in self.results:
            self.greatest_common_filename = max(set(self.results['submission_names']), key=self.results['submission_names'].count)
        return self.results

    def download(self, output_path=None):
        if self.result_type is None:
            self.search()
        if self.url_result:
            # change the resource to the file sha256
            if self.url_result['results']['response_code'] == 0:
                print(result['results']['verbose_msg'])
                return False
            try:
                self.resource = self.url_result['results']['additional_info']['Response content SHA-256']
            except KeyError as e:
                print("Failed to get SHA-256 of content at '{}'".format(self.url))
                return False

        file_name = output_path if output_path else self.resource
        if output_path is None and self.greatest_common_filename is not None:
            file_name = self.greatest_common_filename

        result = self.vt.get_file(self.resource)
        if 'results' in result:
            with open(file_name, 'wb') as fp:
                fp.write(result['results'])
            self.file_path = file_name
            print("+ wrote '{}'".format(file_name))
            return True
        else:
            print(result)
            return False


def build_vt_comment(alert):
    assert isinstance(alert, ace_api.Analysis)

    ace_web_url = 'https://{}/ace/analysis?direct={}'.format(ace_api.default_remote_host, alert.uuid)

    results = ace_api.get_analysis(alert.uuid)['result']
    desc = results['description']

    comment_text = "ACE Result - {}\n\n==============\n\n".format(desc)
    comment_text += "\tLink: {}\n\n".format(ace_web_url)

    observables = results['observable_store']
    tags = results['tags']
    analysis_modules = []
    a_mod_results = {}
    for o_key in observables.keys():
        o_value = observables[o_key]
        tags.extend([tag for tag in o_value['tags'] if tag not in tags])
        a_mods = o_value['analysis']
        a_mod_names = [a[len('saq.modules.'):] for a in a_mods.keys()]
        # update our list
        analysis_modules.extend([a for a in a_mod_names if a not in analysis_modules]) 
        for a_key in a_mods.keys():
            a_mod = a_mods[a_key]
            if a_mod:
                a_mod_results[a_key[len('saq.modules.'):]] = True
                tags.extend([tag for tag in a_mod['tags'] if tag not in tags])
            else:
                a_mod_results[a_key[len('saq.modules.'):]] = False

    for tag in tags:
        comment_text += '#{} '.format(tag)
    comment_text += '\n\n'

    max_type_length = 10
    max_name_length = 30
    a_mod_dict_list = []
    if analysis_modules:
        comment_text += "Analysis Modules used:\n\n"
    for a_mod in analysis_modules:
        parts = a_mod.split(':')
        assert len(parts) == 2
        a_type = parts[0]
        a_name = parts[1]
        if len(a_type) > max_type_length:
            max_type_length = len(a_type)
        if len(a_name) > max_name_length:
            max_name_length = len(a_name)
        a_mod_dict_list.append({'type': a_type,
                                'name': a_name,
                                'result': a_mod_results[a_mod]})
        # putting this here instead of our pretty table
        comment_text += "\t{} - Results: {}\n".format(a_name, a_mod_results[a_mod])

    fmt = [('Type', 'type', max_type_length),
           ('Name', 'name', max_name_length),
           ('Results', 'result', 8)]

    # VT gives no shits about our pretty table
    #print(TablePrinter(fmt, sep='  ', ul='=')(a_mod_dict_list))
    comment_text += '\n'

    return comment_text

def vt_ace_agent(vtr, remote_host, ssl_verification=None, description=None, ignore_proxy=False, uuid=None, force_alert=False, no_comment=False, *args, **kwargs):
    assert isinstance(vtr, VT_Resource)
    analysis_mode = 'analysis'
    if force_alert:
        analysis_mode = 'correlation'

    # Is this resource in VT?
    if not vtr.in_vt:
        print("Unknown to VT: {}".format(vtr.results['verbose_msg']))
        if not force_alert:
            return False
    else:
        print("Resource is in the VT dataset: {}".format(vtr.results['permalink']))

    if ignore_proxy:
        if 'https_proxy' in os.environ:
            del os.environ['https_proxy']
    ace_api.set_default_remote_host(remote_host)
    ace_api.set_default_ssl_ca_path(ssl_verification)
    if description:
        if vtr.greatest_common_filename:
            description = vtr.greatest_common_filename
        else:
            description = vtr.resource
    analysis = ace_api.Analysis(description=description,
                                analysis_mode=analysis_mode,
                                tool='VT ACE Agent')
    cp_result = None
    if uuid:
        analysis.uuid = uuid
    elif vtr.result_type == 'file':
        if not vtr.file_path:
            vtr.download()
        relative_storage_path = vtr.greatest_common_filename if vtr.greatest_common_filename else os.path.basename(vtr.file_path)
        analysis.add_file(vtr.file_path, relative_storage_path=relative_storage_path)
        analysis.submit()
    elif vtr.result_type == 'url':
        cp_result = ace_api.cloudphish_submit(vtr.url)
        #analysis.add_url(vtr.url, directives=['crawl'])
        if 'uuid' in cp_result:
            # this is a little miss-leading
            analysis.uuid = cp_result['uuid']

    if not analysis.uuid:
        print("Problem submitting analysis to ACE : {}".format(analysis))
        return True

    print("Got Analysis UUID = {}".format(analysis.uuid))

    alert = False
    status_check_attempts = 20
    status = analysis.status
    for i in range(status_check_attempts):
        print("\tAnalysis status: {}".format(status))
        if 'COMPLETE' in status:
            try:
                complete = ace_api.get_analysis_status(analysis.uuid)
                alert = complete['result']['alert']
            except:
                pass
            break
        time.sleep(5)
        status = analysis.status
    else:
        print("Gave up waiting for ACE to complete the Analysis.")

    if alert:
        comment_text = build_vt_comment(analysis)
        ace_web_url = 'https://{}/ace/analysis?direct={}'.format(analysis.remote_host, analysis.uuid)
        print("The Analysis became an Alert with {} detections: \n\tUUID = {}\n\tACE URL: {}".format(alert['detection_count'], analysis.uuid, ace_web_url))
        print("\nVT Comment Text:\n")
        print(comment_text)
        if not no_comment:
            pprint.pprint(vtr.make_comment(comment_text))
        print()
    return True

def main():
    DEFAULT_DIR = '/opt/vt-ace-agent/'
    config_path = os.path.join(DEFAULT_DIR, "etc", "vt-ace-agent.ini")
    # if there is a local config, use it
    if os.path.exists(os.path.join("etc", "vt-ace-agent.ini")):
        config_path = os.path.join("etc", "vt-ace-agent.ini")
    try:
        config = ConfigParser()
        config.read(config_path)
    except ImportError:
        raise SystemExit('config was not found or was not accessible.')

    profiles = config.sections()
    profiles.remove('global')
    parser = argparse.ArgumentParser(description="A handy tool for pimping ACE out via comments on VirusTotal.")
    parser.add_argument('-p', '--profile', dest='profile', choices=profiles, default='public', help='select the ace instance. Default: {}'.format(config['public']['remote_host']))
    parser.add_argument('resource', help='either a md5/sha1/sha256 hash, OR a URL, OR a path to a local file')
    parser.add_argument('-n', '--vt-download', action='store_true', help='Download File from VT')
    parser.add_argument('-s', '--vt-search', action='store_true', help="Search for a hash/URL on VT")
    parser.add_argument('-d', '--description', action='store', default=None, help='A description to give the ACE alert (default: resource).')
    parser.add_argument('-u', '--uuid', action='store', help='An alert uuid to use to make the VT comment')
    parser.add_argument('--force-ace-alert', dest='force', action='store_true', help='Analysis mode set to correlation and VT results ignored')
    parser.add_argument('--no-comment', action='store_true', help="Don't comment on VT.")
    args = parser.parse_args()

    proxies = {}
    if 'https_proxy' in os.environ:
        proxies['https'] = os.environ['https_proxy']
    if 'http_proxy' in os.environ:
        proxies['http'] = os.environ['http_proxy']

    vtr = VT_Resource(args.resource, config, proxies=proxies)

    if args.vt_search:
        pprint.pprint(vtr.search())
    elif args.vt_download:
        sys.exit(vtr.download())
    else:
        
        result = vt_ace_agent(vtr, config[args.profile]['remote_host'],
                              ssl_verification=config[args.profile]['ca_bundle_file'],
                              description=args.description,
                              ignore_proxy=config[args.profile].getboolean('ignore_system_proxy'),
                              uuid=args.uuid,
                              force_alert=args.force,
                              no_comment=args.no_comment)
        return result
        analysis_mode = 'analysis'
        if args.force:
            analysis_mode = 'correlation'

        # Is this resource in VT?
        if not vtr.in_vt:
            print("Unknown to VT: {}".format(vtr.results['verbose_msg']))
            if not args.force: 
                sys.exit(0)
        else:
            print("Resource is in the VT dataset: {}".format(vtr.results['permalink']))

        args.no_comment = True if config[args.profile].getboolean('no_vt_comment') else args.no_comment
        remote_host = config[args.profile]['remote_host']
        ssl_ca_path = config[args.profile]['ca_bundle_file']
        if config[args.profile].getboolean('ignore_system_proxy'):
            if 'https_proxy' in os.environ:
                del os.environ['https_proxy']
        ace_api.set_default_remote_host(remote_host)
        ace_api.set_default_ssl_ca_path(ssl_ca_path)
        if not args.description:
            if vtr.greatest_common_filename:
                args.description = vtr.greatest_common_filename
            else:
                args.description = args.resource
        analysis = ace_api.Analysis(description=args.description,
                                    analysis_mode=analysis_mode,
                                    tool='VT ACE Agent')
        cp_result = None
        if args.uuid:
            analysis.uuid = args.uuid
        elif vtr.result_type == 'file':
            if not vtr.file_path:
                vtr.download()
            relative_storage_path = vtr.greatest_common_filename if vtr.greatest_common_filename else os.path.basename(vtr.file_path)
            analysis.add_file(vtr.file_path, relative_storage_path=relative_storage_path)
            analysis.submit()
        elif vtr.result_type == 'url':
            cp_result = ace_api.cloudphish_submit(vtr.url)
            #analysis.add_url(vtr.url, directives=['crawl'])
            if 'uuid' in cp_result:
                # this is a little miss-leading
                analysis.uuid = cp_result['uuid']
 
        if not analysis.uuid:
            print("Problem submitting analysis to ACE : {}".format(analysis))
            sys.exit(1)

        print("Got Analysis UUID = {}".format(analysis.uuid))

        alert = False
        status_check_attempts = 20
        status = analysis.status
        for i in range(status_check_attempts):
            print("\tAnalysis status: {}".format(status))
            if 'COMPLETE' in status:
                try:
                    complete = ace_api.get_analysis_status(analysis.uuid)
                    alert = complete['result']['alert']
                except:
                    pass
                break
            time.sleep(5)
            status = analysis.status
        else:
            print("Gave up waiting for ACE to complete the Analysis.")

        if alert:
            comment_text = build_vt_comment(analysis) 
            ace_web_url = 'https://{}/ace/analysis?direct={}'.format(analysis.remote_host, analysis.uuid)
            print("The Analysis became an Alert with {} detections: \n\tUUID = {}\n\tACE URL: {}".format(alert['detection_count'], analysis.uuid, ace_web_url))
            print("\nVT Comment Text:\n")
            print(comment_text)
            if not args.no_comment:
                pprint.pprint(vtr.make_comment(comment_text))
            print()

if __name__ == '__main__':
    retcode = main()
    exit(retcode)
