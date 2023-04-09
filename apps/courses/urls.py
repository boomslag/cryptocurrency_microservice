from django.urls import path

from .views import *


urlpatterns = [
    path('nft_deploy_price/', GetNFTDeploymentPriceView.as_view()),
    path('nft_deploy/', DeployNFTView.as_view()),
    path('become_affiliate/', BecomeAffiliateView.as_view()),
    path('verify_affiliate/', VerifyAffiliateView.as_view()),
]