'use strict';

/* Services */


// Demonstrate how to register services
// In this case it is a simple value service.
angular.module('roApp.services', ['angularLocalStorage'])
    .factory('SessionService', function ($http, storage) {
        return {
            saveSession: function (data) {
                storage.set('user', data);
            },
            getSession: function () {
                return storage.get('user');
            },
            removeSession: function () {
                storage.clearAll();
            },
            isLoggedIn: function () {
                return storage.get('user') != null;
            },
            saveUserLocations: function (data) {
                storage.set('locations', data);
            },
            getUserLocations: function () {
                return storage.get('locations');
            }
        };
    })

    .factory('mapService', function ($window) {
        // Maps the Location --------------------------------------------------------------------------------->
        return {
            initialize: function (locationList) {
                var locationArray = [];
                var locationNameArray = [];
                var locationIdArray = [];
                var basicLatlng = new google.maps.LatLng(locationList[0].gpsLat, locationList[0].gpsLng);
                //                var bounds = new google.maps.LatLngBounds();
                var mapOptions = {
                    zoom: 3,
                    center: basicLatlng
                };
                var map = new google.maps.Map(document.getElementById('map-canvas'), mapOptions);

                for (var x = 0; x < locationList.length; x++) {
                    locationArray.push(new google.maps.LatLng(locationList[x].gpsLat, locationList[x].gpsLng));
                    locationNameArray.push(locationList[x].locationName);
                    locationIdArray.push(locationList[x].id);
                    //                    bounds.extend(myLatLng);
                    //                    map.fitBounds(bounds);
                }
                var coord;
                var markerArray = [];
                for (coord in locationArray) {
                    var marker = new google.maps.Marker({
                        position: locationArray[coord],
                        map: map,
                        title: locationNameArray[coord],
                        id: locationIdArray[coord]
                    });
                    markerArray.push(marker);
                }
                console.log(markerArray);
                for (var i = 0; i < markerArray.length; i++) {
                    google.maps.event.addListener(markerArray[i], 'click', function () {
                        //                            console.log('Data: ' + this);
                        //                            map.setZoom(8);
                        //                            map.setCenter(marker.getPosition());
                        $window.location = 'index.html#/locationDetails/' + this.id;
                    });
                }


            },
            main: function (locationList) {
                google.maps.event.addDomListener(window, 'load', this.initialize(locationList));
            }
        }
    });