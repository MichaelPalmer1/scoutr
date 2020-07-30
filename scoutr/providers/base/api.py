from abc import abstractmethod

from scoutr.models.request import Request
from scoutr.models.user import User, UserData
from scoutr.providers.base.filtering import Filtering


class BaseAPI:
    filter: Filtering

    @abstractmethod
    def get_config(self):
        raise NotImplementedError

    @abstractmethod
    def can_access_endpoint(self, method: str, path: str, user: User, request: Request) -> bool:
        raise NotImplementedError

    @abstractmethod
    def initialize_request(self, request: Request):
        raise NotImplementedError

    @abstractmethod
    def get_user(self, user_id: str, user_data: UserData):
        raise NotImplementedError

# InitializeRequest(models.Request)(*models.User, error)
# GetUser(string, *models.UserData)(*models.User, error)
# Create(models.Request, map[string] string, map[string]
# utils.FieldValidation) error
# Update(models.Request, map[string]
# string, map[string]
# string, map[string]
# utils.FieldValidation, string) (interface{}, error)
# Get(models.Request, string)(models.Record, error)
# List(models.Request)([]
# models.Record, error)
# ListUniqueValues(models.Request, string)([]
# string, error)
# ListAuditLogs(models.Request, map[string]
# string, map[string]
# string) ([]models.AuditLog, error)
# History(models.Request, string, string, map[string]
# string, []
# string) ([]models.History, error)
# Search(models.Request, string, []
# string) ([]models.Record, error)
# Delete(models.Request, map[string]
# string) error