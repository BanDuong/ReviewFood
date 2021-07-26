import os

from django.http import FileResponse, HttpResponse, JsonResponse
from rest_framework import renderers
from rest_framework.renderers import JSONRenderer


class EmberJSONRenderer(JSONRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):

        if data and 'error' in data and data['error']:
            data = {'status': data['status'],
                    'body': data['body'],
                    'error': data['error']
                    }
        elif data and 'links' in data and data['links']:
            data = {
                'status': 'OK',
                'body': data['data'],
                'error': None,
                'paging': data['links']
            }
        else:
            data = {'status': 'OK',
                    'body': data,
                    'error': None}
        return super(EmberJSONRenderer, self).render(data, accepted_media_type, renderer_context)


class ZipRenderer(renderers.BaseRenderer):
    media_type = 'application/zip'
    format = 'zip'
    charset = None
    render_style = 'binary'
    renderer_context = None

    def render(self, data, media_type=None, renderer_context=None):
        if media_type:
            self.media_type = media_type
        if renderer_context:
            self.renderer_context = renderer_context

        if isinstance(data, dict):
            response = JsonResponse(data)
            return response

        with open(data, 'rb') as file:
            file_name = os.path.basename(data)
            response = HttpResponse(FileResponse(file), content_type='application/zip')
            response['Content-Disposition'] = 'attachment; filename="{}"'.format(file_name)
            return response
