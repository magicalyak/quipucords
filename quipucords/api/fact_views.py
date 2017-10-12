#
# Copyright (c) 2017 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 3 (GPLv3). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv3
# along with this software; if not, see
# https://www.gnu.org/licenses/gpl-3.0.txt.
#

"""Viewset for system facts models"""

from rest_framework import viewsets, mixins
from api.fact_model import FactCollection
from api.fact_serializer import FactCollectionSerializer


# pylint: disable=too-many-ancestors
class FactViewSet(mixins.CreateModelMixin,
                  viewsets.GenericViewSet):
    """
    List all facts, or create a new snippet.
    """
    queryset = FactCollection.objects.all()
    serializer_class = FactCollectionSerializer
