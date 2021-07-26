import math

from rest_framework import pagination
from rest_framework.response import Response


class CustomPagination(pagination.LimitOffsetPagination):
    default_limit = 1

    def get_paginated_response(self, data):
        total_page = math.ceil(self.count / self.limit)
        return Response({
            'links': {
                'prev': self.get_previous_link(),
                'next': self.get_next_link(),
                'count': int(self.count),
                'total_pages': total_page,
            },
            'data': data
        })


class CustomPageNumberPagination(pagination.PageNumberPagination):
    page_size = 1   # có thể setup ở đây hoặc file settings/default
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response({
            'links': {
                'prev': self.get_previous_link(),
                'next': self.get_next_link(),
                'count': self.page.paginator.per_page,
                'total_record': self.page.paginator.count,
            },
            'data': data
        })


class CustomPageNumberPagination20(pagination.PageNumberPagination):
    page_size = 20

    def get_paginated_response(self, data):
        return Response({
            'links': {
                'prev': self.get_previous_link(),
                'next': self.get_next_link(),
                'count': self.page.paginator.per_page,
                'total_record': self.page.paginator.count,
            },
            'data': data
        })


class NewPageNumberPagination(pagination.PageNumberPagination):
    page_size = 10

    def get_paginated_response(self, data):
        return Response({
            'links': {
                'prev': self.get_previous_link(),
                'next': self.get_next_link(),
                'count': self.page.paginator.per_page,
                'total_record': self.page.paginator.count,
            },
            'data': data
        })
