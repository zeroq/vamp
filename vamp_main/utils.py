
from vamp_main.myservices import service_dict

from vamp_scans.models import Finding

def get_service_name(port, protocol):
    try:
        items = service_dict['%s/%s' % (port, protocol.lower())]
        return items[-1]
    except:
        items = None
    if items is None:
        try:
            fobjs = Finding.objects.filter(port=port, protocol=protocol).distinct()
        except Finding.DoesNotExist:
            return 'general'
        if len(fobjs)>0:
            return fobjs[0].service
    return 'general'
