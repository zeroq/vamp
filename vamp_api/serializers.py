
from rest_framework import serializers

from vamp_api.models import TenableAPI
from vamp_scans.models import Host, Finding, Comment, Tag, HostComment
from vamp_exceptions.models import Exceptions

class ExceptionSerializer(serializers.ModelSerializer):
    host_name = serializers.CharField(source='host.name')
    vuln = serializers.CharField(source='finding.short')
    approved = serializers.SerializerMethodField()

    class Meta:
        model = Exceptions
        fields = '__all__'

    def get_approved(self, obj):
        if obj.approved == False:
            return '<span class="label label-danger">False</span>'
        else:
            return '<span class="label label-success">True</span>'

class TenableAPISerializer(serializers.ModelSerializer):
    class Meta:
        model = TenableAPI
        fields = ('id', 'server', 'severities')

class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ('id','tag', 'description', 'ttype')


class HostCommentSerializer(serializers.ModelSerializer):
    author = serializers.SerializerMethodField()
    
    class Meta:
        model = HostComment
        fields = '__all__'
    
    def get_author(self, obj):
        return obj.author.username

class CommentSerializer(serializers.ModelSerializer):
    author = serializers.SerializerMethodField()

    class Meta:
        model = Comment
        fields = '__all__'

    def get_author(self, obj):
        return obj.author.username

class FindingHostsSerializer(serializers.ModelSerializer):
    host_id = serializers.IntegerField(source='host.id')
    host_name = serializers.CharField(source='host.name')
    status = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = ['host_name', 'host_id', 'status']

    def get_status(self, obj):
        display_name = obj.get_status_display()
        return display_name


class FindingDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding
        fields = '__all__'


class FindingSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    severity = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = ['id', 'name', 'service', 'port', 'source', 'severity', 'status', 'first_seen', 'last_seen', 'cve', 'exploit_available', 'exploited_in_the_wild', 'short', 'tags']

    def get_severity(self, obj):
        display_name = obj.get_severity_display()
        if obj.severity == 1:
            return '<span class="label label-success">'+str(display_name)+'</span>'
        elif obj.severity == 2:
            return '<span class="label label-warning">'+str(display_name)+'</span>'
        elif obj.severity == 3:
            return '<span class="label label-danger">'+str(display_name)+'</span>'
        elif obj.severity == 4:
            return '<span class="label label-default">'+str(display_name)+'</span>'
        else:
            return '<span class="label label-info">'+str(display_name)+'</span>'

    def get_status(self, obj):
        display_name = obj.get_status_display()
        WORKAROUND = 2, 'workaround'
        EXCEPTION = 3, 'exception'
        FALSE = 4, 'false'
        IGNORE = 5, 'ignore'
        if obj.status == 0:
            return '<span class="label label-danger">'+str(display_name)+'</span>'
        elif obj.status == 1:
            return '<span class="label label-success">'+str(display_name)+'</span>'
        elif obj.status == 2:
            return '<span class="label label-primary">'+str(display_name)+'</span>'
        elif obj.status == 3:
            return '<span class="label label-warning">'+str(display_name)+'</span>'
        elif obj.status == 4:
            return '<span class="label label-info">'+str(display_name)+'</span>'
        else:
            return '<span class="label label-default">'+str(display_name)+'</span>'

class TopFindingSerializer(serializers.ModelSerializer):
    assets = serializers.IntegerField()
    severity = serializers.SerializerMethodField()
    exploited_in_the_wild = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = ['severity', 'exploited_in_the_wild', 'short', 'assets', 'id']

    def get_exploited_in_the_wild(self, obj):
        if obj['exploited_in_the_wild'] is True:
            return '<span class="label label-danger">True</span>'
        else:
            return '<span class="label label-success">False</span>'

    def get_severity(self, obj):
        if obj['severity'] == 1:
            return '<span class="label label-success">low</span>'
        elif obj['severity'] == 2:
            return '<span class="label label-warning">medium</span>'
        elif obj['severity'] == 3:
            return '<span class="label label-danger">high</span>'
        elif obj['severity'] == 4:
            return '<span class="label label-default">critical</span>'
        else:
            return '<span class="label label-info">information</span>'

class HostSerializer(serializers.ModelSerializer):
    tags = serializers.SerializerMethodField()

    class Meta:
        model = Host
        fields = ['id', 'name', 'fqdn', 'netbios_name', 'ip', 'rdns', 'os', 'first_scan', 'last_scan', 'tags']

    def get_tags(self, obj):
        res = []
        for item in obj.tags.all():
            try:
                if item.description == None:
                    item.description = ''
                if item.ttype == 2:  # automatic tags
                    res.append('<div rel="tooltip" data-placement="right" data-original-title="'+item.description+'"><span class="label label-primary" style="background-color: #E20074">'+item.tag+'</span></div>')
                else:
                    res.append('<div rel="tooltip" data-placement="right" data-original-title="'+item.description+'"><span class="label label-primary" style="background-color: #23819C">'+item.tag+'</span></div>')
            except:
                continue
        return "".join(res)

class VulnHostSerializer(serializers.ModelSerializer):
    vuln_crit = serializers.IntegerField()
    vuln_high = serializers.IntegerField()
    vuln_med = serializers.IntegerField()
    vuln_low = serializers.IntegerField()
    vulns = serializers.SerializerMethodField()

    class Meta:
        model = Host
        fields = ['id', 'name', 'fqdn', 'netbios_name', 'ip', 'rdns', 'os', 'first_scan', 'last_scan', 'tags', 'vuln_crit', 'vuln_high', 'vuln_med', 'vuln_low', 'vulns']

    def get_vulns(self, obj):
        return '<span class="label label-default">'+str(obj.vuln_crit)+'</span><span class="label label-danger">'+str(obj.vuln_high)+'</span><span class="label label-warning">'+str(obj.vuln_med)+'</span><span class="label label-success">'+str(obj.vuln_low)+'</span>'
