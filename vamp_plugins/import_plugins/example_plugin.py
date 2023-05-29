

class importPlugin(object):

    def __init__(self):
        self.plugin_name = "Example Import Plugin"

    def process_host(self, data):
        """modify host entry before import
        """
        try:
            ### data is a host dictionary
            pass
        except Exception as error:
            print(error)
        return data

    def process_finding(self, data):
        """modify finding entry before import
        """
        try:
            ### data is a finding dictionary
            if 'cve' in data:
                print(data)
        except Exception as error:
            print(error)
        return data
