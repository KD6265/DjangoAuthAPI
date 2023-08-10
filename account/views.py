from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer ,UserLoginSerializer, UserProfileSerializer,UserChangePasswordSerializer,UserRestPasswordEmailSerializer,UserSetRestPasswordSerializer
from django.contrib.auth import  authenticate
from .renderers import UserRenderers
from rest_framework_simplejwt.tokens import RefreshToken
from  rest_framework.permissions import IsAuthenticated

# Create your views here.

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
class UserRegistrationView(APIView):
    renderer_classes =[UserRenderers]
    def post(self, request, format = None, *args, **kwargs ):
        print("Print data",request)
        serializer =  UserRegistrationSerializer(data = request.data)
        print("serializer Print : ",serializer)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            print("print user : ",user)
            token = get_tokens_for_user(user)
            return Response({'msg': 'user registration  successfully','token':token},status=status.HTTP_201_CREATED
                            )
        print("Serializer errors:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    renderer_classes =[ UserRenderers]
    def post(self, request,format=None,*args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        print("User login Serializer data: ",serializer, )
        if serializer.is_valid():
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                print("User: %s" % user)
                token = get_tokens_for_user(user)
                return Response({'msg':"User login is successfully",'token':token},status=status.HTTP_200_OK)
            else :
                return Response({'error':{'non_fields_error':['Email and Password is not valid']}},status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    
class UserProfileView(APIView):
    renderer_classes= [UserRenderers]
    permission_classes = [IsAuthenticated]
    def get(self, request,format=None, *args, **kwargs):
        print('user request',request.user)
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderers]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None,*args, **kwargs):
        serializer = UserChangePasswordSerializer(data=request.data,context= {'user': request.user})
        if serializer.is_valid():
            return Response({'msg':'User changed password successfully'}, status = status.HTTP_200_OK)
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

class UserRestPasswordEmailView(APIView):
    renderer_classes = [UserRenderers]
    def post(self, request,format=None, *args, **kwargs):
        serializer =  UserRestPasswordEmailSerializer(data= request.data)
        if serializer.is_valid():
            return Response({'msg':'Password reset link send. please check your email '}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserSetRestPasswordView(APIView):
    renderer_classes =[ UserRenderers]
    def post(self, request,uid,token,format=None,*args,**kwargs):
        serializer = UserSetRestPasswordSerializer(data=request.data,context={'uid':uid, 'token':token})
        if serializer.is_valid(raise_exception=True):
            # serializer.save()
            return Response({'msg':'user reset password successfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD )
