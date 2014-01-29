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
from rest_framework.authentication import get_authorization_header
from rest_framework import permissions

# -------------------------------

from django.shortcuts import render
from rest_framework import permissions
from rest_framework import viewsets
from rest_framework import views
from rest_framework import parsers
from rest_framework import renderers
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.authtoken.models import Token

from social.apps.django_app.utils import strategy
from social.apps.django_app.views import _do_login

# -------------------------------

from django.contrib.auth.models import User
from .models import *
from .serializers import *


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

@api_view(('GET',))
def comments_by_location(request):
    location_id = request.QUERY_PARAMS['locationID']
    queryset = Comment.objects.filter(locationPostID = location_id)
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


class ObtainAuthToken2(views.APIView):  # generics.RetrieveUpdateDestroyAPIView
    throttle_classes = ()
    permission_classes = ()
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = AuthTokenSerializer
    model = Token

    def get(self, r):
        return []

    # Accept backend as a parameter and 'auth' for a login / pass
    def post(self, request, backend='google'):
        print 'backend'
        serializer = self.serializer_class(data=request.DATA)

        if backend == 'auth':
            if serializer.is_valid():
                token, created = Token.objects.get_or_create(user=serializer.object['user'])
                return Response({'token': token.key})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        else:
            print "Here"
            # Here we call PSA to authenticate like we would if we used PSA on server side.
            user = register_by_access_token(request, backend)

            # If user is active we get or create the REST token and send it back with user data
            if user and user.is_active:
                token, created = Token.objects.get_or_create(user=user)
                return Response({'id': user.id , 'name': user.username, 'userRole': 'user','token': token.key})

@strategy()
def register_by_access_token(request, backend):
    backend = request.strategy.backend
    # Split by spaces and get the array
    auth = get_authorization_header(request).split()

    if not auth or auth[0].lower() != b'token':
        msg = 'No token header provided.'
        return msg

    if len(auth) == 1:
        msg = 'Invalid token header. No credentials provided.'
        return msg

    access_token = auth[1]
    # Real authentication takes place here
    user = backend.do_auth(access_token)

    return user