from django.db import models

# Create your models here.
class ApkScan(models.Model):
    file_name = models.CharField(max_length=255)
    file_path = models.CharField(max_length=255)
    package = models.CharField(max_length=255, null=True)
    main_activity = models.CharField(max_length=255, null=True)
    activities = models.TextField(null=True)
    services = models.TextField(null=True)
    receivers = models.TextField(null=True)
    providers = models.TextField(null=True)
    permissions = models.TextField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)



class ApkFile(models.Model):
    file_name = models.CharField(max_length=255)
    file_path = models.CharField(max_length=255)
    md5 = models.CharField(max_length=32, unique=True)
    upload_time = models.DateTimeField(auto_now=True)
    package_name = models.CharField(max_length=255, null=True, blank=True)
    app_icon_base64 = models.TextField(null=True, blank=True)
    static_analyzed = models.BooleanField(default=False)
    dynamic_analyzed = models.BooleanField(default=False)
    prediction_result = models.IntegerField(null=True, blank=True)
    gcn_prediction_result = models.IntegerField(null=True, blank=True)
    confidence = models.FloatField(null=True, blank=True)  # 添加置信度字段
    gcn_confidence = models.FloatField(null=True, blank=True)  # 添加GCN置信度字段
    lime_explanation_path = models.CharField(max_length=255, null=True, blank=True)
    lime_explanation_path_multi = models.CharField(max_length=255, null=True, blank=True)
    app_name = models.CharField(max_length=255, null=True, blank=True)
    version_name = models.CharField(max_length=255, null=True, blank=True)
    word_report_path_static = models.CharField(max_length=255, null=True, blank=True)
    pdf_report_path_static = models.CharField(max_length=255, null=True, blank=True)
    word_report_path_model = models.CharField(max_length=255, null=True, blank=True)
    pdf_report_path_model = models.CharField(max_length=255, null=True, blank=True)
    static_analysis_result = models.JSONField(null=True, blank=True)
    def __str__(self):
        return self.file_name

class WhiteBlackRecord(models.Model):
    file_name = models.CharField(max_length=255)
    md5_value = models.CharField(max_length=32)
    sha256_value = models.CharField(max_length=64, unique=True)
    category = models.CharField(max_length=100, choices=[('white', 'White'), ('scam', 'Scam')])

    def __str__(self):
        return self.file_name