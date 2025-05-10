from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
urlpatterns = [
    path('', views.home, name='home'),
    path('about_us/', views.about_us, name='about_us'),
    path('static_ana/<str:file_name>/', views.static_ana, name='static_ana'),
    path('dynamic_ana/', views.dynamic_ana, name='dynamic_ana'),
    path('upload_and_static_ana/', views.upload_and_static_ana, name='upload_and_static_ana'),
    path('upload_and_dynamic_ana/', views.upload_and_dynamic_ana, name='upload_and_dynamic_ana'),
    path('upload_model_predict/', views.upload_model_predict, name='upload_model_predict'),
    path('black_white_filter/', views.black_white_filter, name='black_white_filter'),
    path('model_predict/<str:apk_file_name>/', views.model_predict, name='model_predict'),
    path('delete_apk/<str:apk_file_name>/', views.delete_apk, name='delete_apk'),
    path('result_page/', views.result_page, name='result_page'),
    path('recent_scan/', views.recent_scan, name='recent_scan'),
    path('download_model/', views.download_model, name='download_model'),
    path('download_project/', views.download_project, name='download_project'),
    path('handle_qr_code_upload/', views.handle_qr_code_upload, name='handle_qr_code_upload'),
    path('handle_download_link_upload/', views.handle_download_link_upload, name='handle_download_link_upload'),
    path('handle_qr_code_upload_static/', views.handle_qr_code_upload_static, name='handle_qr_code_upload_static'),
    path('handle_download_link_upload_static/', views.handle_download_link_upload_static, name='handle_download_link_upload_static'),
    path('rescan_apk/', views.rescan_apk, name='rescan_apk'),
    path('static_predict_apk/', views.static_predict_apk, name='static_predict_apk'),
    path('static_export_report/', views.static_export_report, name='static_export_report'),
    path('download_report_zip/<str:apk_file_name>/', views.download_report_zip, name='download_report_zip'),

]

