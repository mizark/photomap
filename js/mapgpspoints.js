$("document").ready(function(){
        
        tempurl=$('.post-title-link').attr("href")
        
	$.ajax({ 
		type: 'GET', 
		url: tempurl+'.json', 
	
		success: function (data) {
                           
			var divs=document.getElementsByClassName('map_canvas')
                        if($.isArray(data)){
                           for(var x=0; x<data.length; x++){
		              
			     if(data[x].latitude_list.length!==0){
                               var mapOptions = {
                                 center: new google.maps.LatLng(data[x].latitude_list[0],data[x].longitude_list[0]), zoom: 6,
                                 mapTypeId: google.maps.MapTypeId.HYBRID,
			         backgroundColor: 'white',
                               };
                             

                               var map = new google.maps.Map(divs[x],mapOptions);
			       for(var y=0; y<data[x].latitude_list.length;y++){
			         var marker = new google.maps.Marker({
				      position: new google.maps.LatLng(data[x].latitude_list[y],data[x].longitude_list[y]),
                                      map:map,
			         });
			       }
			     } else{

				 var mapOptions = {
					center: new google.maps.LatLng(data[x].city_latitude,data[x].city_longitude),
					zoom:6,
					mapTypeId: google.maps.MapTypeId.HYBRID,
					backgroundColor:'white',
				 };

				 var map = new google.maps.Map(divs[x],mapOptions);
				 var marker = new google.maps.Marker({
					position: new google.maps.LatLng(data[x].city_latitude,data[x].city_longitude),
					map:map,
				 });
			     }

			
			   }
                        } else {


			     if (data.latitude_list.length !== 0){
			       var mapOptions = {
                                 center: new google.maps.LatLng(data.latitude_list[0],data.longitude_list[0]), zoom: 5,
                                 mapTypeId: google.maps.MapTypeId.HYBRID
                               };

                               var map = new google.maps.Map(divs[0],mapOptions);
			       for(var z=0; z<data.latitude_list.length; z++){  
			         var marker= new google.maps.Marker({
				      position: new google.maps.LatLng(data.latitude_list[z],data.longitude_list[z]),
				      map:map, title: data.city+","+data.state,
			         });
			       }

			     } else{
				 var mapOptions = {
                                        center: new google.maps.LatLng(data.city_latitude,data.city_longitude),
                                        zoom:6,
                                        mapTypeId: google.maps.MapTypeId.HYBRID,
                                        backgroundColor:'white',
                                 };

                                 var map = new google.maps.Map(divs[0],mapOptions);
                                 var marker = new google.maps.Marker({
                                        position: new google.maps.LatLng(data.city_latitude,data.city_longitude),
                                        map:map,
                                 });
                             }

			}


		},
		
        });

        

        
      })
