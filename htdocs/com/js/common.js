function IsPC()  
{  
    var userAgentInfo = navigator.userAgent;  
    var Agents = new Array("Android", "iPhone", "SymbianOS", "Windows Phone", "iPad", "iPod");  
    var flag = true;  
    for (var v = 0; v < Agents.length; v++) {  
       if (userAgentInfo.indexOf(Agents[v]) > 0) { flag = false; break; }  
    } 
    //alert(flag);
    return flag;  
}

$(document).ready(function(){
    //返回顶部
    $("#gototop").click(function(){
      $("html,body").animate({scrollTop :0}, 800);return false;
    });
    $("#gotocate").click(function(){
       $("html,body").animate({scrollTop:$("#classification").offset().top - 50},800);
       return false;
    });

    $("ul.menu_body").each(function(){
    if ($(this).text().replace(/[\r\n ]/g,"").length<=0) {$(this).prev().remove();} //去掉span
    });

    $("#firstpane span").click(function(){
      var spanatt = $(this).next("ul").css('display');
      if (spanatt == "block"){
          var spantext = "+";
          // $(this).prev().removeClass("left_active");
      }else{
          var spantext = "-";
          //$(this).prev().addClass("left_active");
      }
      $(this).html(spantext).addClass("current").next("ul").slideToggle(300).siblings("ul");
    });
    //导航无分类就隐藏
    if($("#firstpane").children().length == 0)
    {
        $("#classification").hide();
    }
    if($(".firstSelected") != null)
    {
        $(".firstSelected").next("span").html("-");
        $(".firstSelected").next("span").next("ul").slideToggle(300);
    }
  
    $("#smallSearch").click(function(){
        $(".searchBox").slideToggle();
    });
});

//把导航中没有子元素的ul和展开按钮删除
$('.dropdown').each(function(i){
	var len = $(this).children(".dropdown-menu").children().length;
	if(len==0)
	{
	    $(this).children("#app_menudown").hide();
	    $(this).children(".dropdown-menu").hide();
	    
	    $(this).children('.dropdown-toggle').dropdownHover();
        $(this).children('a.dropdown-toggle').one('click',function(){ location.href= $(this).attr('href'); });
	}
})

//如果是电脑版的就鼠标悬停展开下级菜单
if($(window).width() >= 768 && IsPC())
{
    $('.dropdown-toggle').dropdownHover();
    $('a.dropdown-toggle').one('click',function(){ location.href= $(this).attr('href'); });
    $(".dropdown-menu li").hover(function(){$(this).children("ul").toggle();}); 
}

//底部产品
$(".bottomButton").click(function(){
    for(var i = 1;i < 4;i++)
    {
        if ($(this).attr('id') == "bottomProductBtn" + i) {
            $("#bottomProductBtn" + i).addClass("selectedBottomButton");
            $("#bottomProductList" + i).show();
            $("#bottomProductTitle" + i).show();
        } else {
            $("#bottomProductBtn" + i).removeClass("selectedBottomButton");
            $("#bottomProductList" + i).hide();
            $("#bottomProductTitle" + i).hide();
        }
    }
});

function utf16to8(str) {  
    var out, i, len, c;  
    out = "";  
    len = str.length;  
    for(i = 0; i < len; i++) {  
    c = str.charCodeAt(i);  
    if ((c >= 0x0001) && (c <= 0x007F)) {  
        out += str.charAt(i);  
    } else if (c > 0x07FF) {  
        out += String.fromCharCode(0xE0 | ((c >> 12) & 0x0F));  
        out += String.fromCharCode(0x80 | ((c >>  6) & 0x3F));  
        out += String.fromCharCode(0x80 | ((c >>  0) & 0x3F));  
    } else {  
        out += String.fromCharCode(0xC0 | ((c >>  6) & 0x1F));  
        out += String.fromCharCode(0x80 | ((c >>  0) & 0x3F));  
    }  
    }  
    return out;  
} 