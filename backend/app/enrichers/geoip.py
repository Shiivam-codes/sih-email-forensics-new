from pathlib import Path
from typing import Any

import geoip2.database
from geoip2.errors import AddressNotFoundError


class GeoIpDatabase:
    def __init__(self, city_path: str, asn_path: str) -> None:
        self.city_reader = self._open(city_path)
        self.asn_reader = self._open(asn_path)
        self.city_error: str | None = None
        self.asn_error: str | None = None

    @staticmethod
    def _open(path: str) -> geoip2.database.Reader | None:
        if not Path(path).is_file():
            return None
        try:
            return geoip2.database.Reader(path)
        except (OSError, ValueError):
            return None

    @property
    def available(self) -> bool:
        return self.city_reader is not None or self.asn_reader is not None

    @property
    def detail(self) -> str | None:
        if self.available:
            return None
        return "GeoIP database not found or could not be opened"

    def lookup(self, ip: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.city_reader is not None:
            try:
                city = self.city_reader.city(ip)
                result.update(
                    {
                        "country": city.country.name,
                        "country_code": city.country.iso_code,
                        "city": city.city.name,
                        "region": (
                            city.subdivisions.most_specific.name if city.subdivisions else None
                        ),
                        "latitude": city.location.latitude,
                        "longitude": city.location.longitude,
                        "timezone": city.location.time_zone,
                    }
                )
            except AddressNotFoundError:
                pass
            except Exception:
                self.city_error = "GeoIP city lookup failed"
        if self.asn_reader is not None:
            try:
                asn = self.asn_reader.asn(ip)
                result.update(
                    {
                        "asn": asn.autonomous_system_number,
                        "as_org": asn.autonomous_system_organization,
                    }
                )
            except AddressNotFoundError:
                pass
            except Exception:
                self.asn_error = "GeoIP ASN lookup failed"
        return {key: value for key, value in result.items() if value is not None}

    def close(self) -> None:
        if self.city_reader is not None:
            self.city_reader.close()
        if self.asn_reader is not None:
            self.asn_reader.close()
