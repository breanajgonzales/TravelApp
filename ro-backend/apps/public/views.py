from django.shortcuts import render_to_response
from django.http import HttpResponse
from django.contrib import auth
from rest_framework.renderers import JSONRenderer
from rest_framework.decorators import api_view
from django.core.context_processors import csrf
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework import status

from rest_framework.authtoken.views import ObtainAuthToken

from rest_framework import generics
from rest_framework import permissions

from django.contrib.auth.models import User
from .models import *
from serializers import *


# Create your views here.
class JSONResponse(HttpResponse):
    def __init__(self, data, **kwargs):
        content = JSONRenderer().render(data)
        kwargs['content_type'] = 'application/json'
        super(JSONResponse, self).__init__(content, **kwargs)


class UserList(generics.ListCreateAPIView):
    """List all users or create a new User"""
   # permission_classes = (permissions.IsAuthenticated,)
    model = User
    serializer_class = UserSerializer


class UserDetail(generics.RetrieveAPIView):
    """Retrieve, update or delete a User instance."""
    permission_classes = (permissions.IsAuthenticated,)
    model = User
    serializer_class = UserSerializer


# I Added this stuff --------------------------------------

class LocationList(generics.ListCreateAPIView):
    """List all Locations or create a new Location"""
    #permission_classes = (permissions.IsAuthenticated,)
    model = Location
    serializer_class = LocationSerializer

class LocationDetail(generics.RetrieveUpdateDestroyAPIView):
    """List all Locations or create a new Location"""
    #permission_classes = (permissions.IsAuthenticated,)
    model = Location
    serializer_class = LocationSerializer

class CommentList(generics.ListCreateAPIView):
    """List all Locations or create a new Location"""
    permission_classes = (permissions.IsAuthenticated,)
    model = Comment
    serializer_class = CommentSerializer
    # queryset = Comment.objects.filter(locationPostID = location_id)

    # def get(self, request):
    #     print "%s" % request.QUERY_PARAMS['locationID']
    #     location_id = request.QUERY_PARAMS['locationID']
    #     return query_set

# I Added the stuff above --------------------------------------

@api_view(('GET',))
def comments_by_location(request):
    location_id = request.QUERY_PARAMS['locationID']
    queryset = Comment.objects.filter(locationPostID=location_id)
    serializer_class = CommentSerializer(queryset)

        # print "%s" % request.QUERY_PARAMS['locationID']
    return Response(serializer_class.data)


class AddressList(generics.ListCreateAPIView):
    """List all addresses or create a new Address"""
    permission_classes = (permissions.IsAuthenticated,)
    model = Address
    serializer_class = AddressSerializer


class AddressDetail(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update or delete an Address."""
    permission_classes = (permissions.IsAuthenticated,)
    model = Address
    serializer_class = AddressSerializer

@api_view(('POST',))
def authenticate(request):
    c = {}
    c.update(csrf(request))

    username = request.POST.get('username', request.DATA['username'])  # emtpy string if no username exists
    password = request.POST.get('password', request.DATA['password'])  # empty string if no password exists

    user = auth.authenticate(username=username, password=password)

    if user is not None:
        auth.login(request, user)
        return Response(UserSerializer(user).data, status=status.HTTP_200_OK)
    else:
        c['message'] = 'Login failed!'
        return render_to_response('partials/login.tpl.html', c)

@api_view(('GET',))
def obtain_user_from_token(r, token):
   auth = TokenAuthentication()
   response = auth.authenticate_credentials(token)
   user_id = response[0].id
   return Response(user_id)

@api_view(('GET',))
def uploadedimages(request, location_id):
    location = Location.objects.get(id=location_id)
    photo_name = location.photos.name.split("/")[-1]
    # if request.method == 'GET':
    #     logo = Logo.objects.get(consultant_id=company.consultant_id)
    if request.is_secure():
        photo_url = ''.join(['https://', request.META['HTTP_HOST'], '/static/', photo_name])
    else:
        photo_url = ''.join(['http://', request.META['HTTP_HOST'], '/static/', photo_name])

    response = [photo_url, location_id]
    return Response(response)

def logout(request):
    auth.logout(request)
    return JSONResponse([{'success': 'Logged out!'}])

class NewAuthToken(ObtainAuthToken):
   def post(self, request):
       serializer = self.serializer_class(data=request.DATA)
       if serializer.is_valid():
           token, created = Token.objects.get_or_create(user=serializer.object['user'])
           data = {
               'user': UserSerializer(User.objects.filter(auth_token=token)).data,
               'token': token.key,
           }
           return Response(data)
       return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)