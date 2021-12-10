from django.db import connection


class QueryCountDebugMiddleware(object):
    """Debug query count - use for DEBUG only."""
    """
    This middleware will log the number of queries run
    and the total time taken for each request (with a
    status code of 200). It does not currently support
    multi-db setups.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        total_time = 0

        for query in connection.queries:
            query_time = query.get('time')
            print(str(query))

            if query_time is None:
                query_time = query.get('duration', 0) / 1000
            total_time += float(query_time)

        print('%s queries run, total %s seconds' % (len(connection.queries), total_time))
        return response

class ABCD(QueryCountDebugMiddleware):

    def __call__(self, request):
        accesstoken = request.COOKIES['access_token']
        get_refresh_token = rd.get(refresh_token)
        if accesstoken:
           try:
            # access còn hạn
            user =  jwt.decode(accesstoken, key, hs256)
            request['user_id'] = user['id']
            return user
           except Exception as e:
                # access hết hạn
                if type(e) == jwt.exceptions.ExpiredSignatureError:
                    new_token = get_refresh_token.access_token
                    response.set_cookie(key='access_token', value=new_token, httponly=True)
                else:
                    raise
        else:
            pass

        request['Authorization'] = request.COOKIES['access_toke
