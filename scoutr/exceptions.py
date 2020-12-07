class HttpException(Exception):
    status = 500

    def __init__(self, status=500, *args, **kwargs):
        self.status = status
        super(HttpException, self).__init__(*args, **kwargs)


class BadRequestException(HttpException):
    status = 400

    def __init__(self, *args, **kwargs):
        super(HttpException, self).__init__(*args, **kwargs)


class ForbiddenException(HttpException):
    status = 401

    def __init__(self, *args, **kwargs):
        super(HttpException, self).__init__(*args, **kwargs)


class UnauthorizedException(HttpException):
    status = 403

    def __init__(self, *args, **kwargs):
        super(HttpException, self).__init__(*args, **kwargs)


class NotFoundException(HttpException):
    status = 404

    def __init__(self, *args, **kwargs):
        super(HttpException, self).__init__(*args, **kwargs)


class InvalidUserException(BadRequestException):
    pass
