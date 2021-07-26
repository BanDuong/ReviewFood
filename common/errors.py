from _datetime import datetime

from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.views import exception_handler

from mysite.settings import DEBUG


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    # Now add the HTTP status code to the response.
    if isinstance(exc, PageNotFound):
        response.data = None
        return response

    if response is not None:
        if exc and not hasattr(exc, 'default_code'):
            code = "not_found"
        else:
            code = exc.default_code
        message = exc.detail
        response.data = {
            'status': "ERROR",
            'body': None,
            'error': {
                'message': message,
                'code': code,
                'timestamp': datetime.now(),
            }
        }
        if DEBUG and hasattr(exc, 'err') and exc.err is not None:
            if hasattr(exc.err, 'detail'):
                response.data['error']['log'] = exc.err.detail
            else:
                response.data['error']['log'] = f'{type(exc.err)} {str(exc.err)}'

        response.content_type = 'application/json'

    return response


class PageNotFound(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = 'Not found.'
    default_code = 'not_found'


class ErrInternal(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'something went wrong in the server'
    default_code = 'ErrInternal'


class ErrAppEntity(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Can not list entity '
    default_code = 'ErrCannotList'

    def __init__(self, detail=None, code=None, entity=None, err=None):
        if entity is None:
            entity = ''

        self.detail = f'{self.default_detail}{entity}'.strip()
        self.default_code = f'{self.default_code}{entity.replace(" ","")}' # edited here
        self.err = err


class ErrCannotListEntity(ErrAppEntity):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Can not list entity '
    default_code = 'ErrCannotList'


class ErrCannotDeleteEntity(ErrAppEntity):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Can not delete entity '
    default_code = 'ErrCannotDelete'


class ErrCannotCreateEntity(ErrAppEntity):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Can not create entity '
    default_code = 'ErrCannotCreate'


class ErrCannotUpdateEntity(ErrAppEntity):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Can not update entity '
    default_code = 'ErrCannotUpdate'



class ErrCannotGetEntity(ErrAppEntity):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Can not get entity '
    default_code = 'ErrCannotGet'


class ErrAppException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'invalid request'
    default_code = 'ErrInvalidRequest'

    def __init__(self, detail=None, code=None, entity=None, err=None):
        if entity is None:
            entity = ''

        self.detail = f'{self.default_detail}{entity}'.strip()
        self.default_code = f'{self.default_code}{entity}'
        self.err = err


class ErrInvalidRequest(ErrAppException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'invalid request'
    default_code = 'ErrInvalidRequest'


class ErrUnauthorized(ErrAppEntity):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'invalid token'
    default_code = 'UNAUTHORIZED'

#-----------------USER------------------------#

class ErrLogin(ErrAppException):
    """exception login"""
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Login Failed '
    default_code = 'ErrorLogin'

class ErrViewUser(ErrAppException):
    """exception display user infor"""
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'View User Failed '
    default_code = 'ErrorViewUser'
