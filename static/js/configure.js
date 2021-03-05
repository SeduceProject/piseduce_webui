// Global variables
const NODE_TYPES = [ "raspberry", "sensor", "server", "fake" ];

// Display nodes from their type
$(document).ready(function () {
    var hideMe = false;
    var no_node = true;
    NODE_TYPES.forEach(function(nodeType) {
        var nodeHMTL = $("#" + nodeType);
        var activeMe = true;
        if(nodeHMTL.children().length > 0) {
            no_node = false;
            if(activeMe) {
                $("#" + nodeType + "-button").addClass("active");
                activeMe = false;
            }
        } else {
            $("#" + nodeType + "-button").addClass("disabled");
        }
    });
    if(no_node) {
        $(".node-config").html("<center>" +
            "No node in the 'configuring' state!<br/>" +
            "<a href='/user/reserve'>Go to the reservation page</a>" +
            "</center>");
    }
});

// Functions
function copyConfiguration(nodeName) {
    var inputConfig = [];
    var selectConfig = [];
    $(".card-header").each(function(useless, node) {
        nodeHTML = node.innerHTML.replace(/\s/g,'');
        if(inputConfig.length > 0) {
            $(node).removeClass("font-weight-bold");
            $("#" + nodeHTML + "-props").find(".col").children("input").each(function(idx, input) {
                $(input).val(inputConfig[idx]);
            });
            $("#" + nodeHTML + "-props").find(".col").children("select").each(function(idx, select) {
                $(select).val(selectConfig[idx]);
            });
        }
        if(nodeHTML == nodeName) {
            $(node).addClass("font-weight-bold");
            $("#" + nodeName + "-props").find(".col").children("input").each(function(idx, input) {
                inputConfig.push($(input).val());
            });
            $("#" + nodeName + "-props").find(".col").children("select").each(function(idx, select) {
                selectConfig.push($(select).val());
            });
        }
    });
}

function removeBold(headerId) {
    $("#" + headerId).removeClass("font-weight-bold");
}

function nodeSelection(buttonType) {
    if(!$("#" + buttonType + "-button").hasClass("disabled") && !$("#" + buttonType + "-button").hasClass("active")) {
        console.log(buttonType);
        NODE_TYPES.forEach(function(type) {
            var button = $("#" + type + "-button");
            if(type == buttonType) {
                button.addClass("active");
                $("#" + type).show();
            } else {
                button.removeClass("active");
                $("#" + type).hide();
            }
        });
    }
}

function showDesc(inputTag) {
    var propName = $(inputTag).attr("name");
    if(propName.includes("-")) {
        propName = propName.split("-");
        propName = propName[propName.length - 1];
    }
    switch(propName) {
        case "duration":
            desc = "The duration of the deployment in hours. The maximum value is 72 hours.";
            break;
        case "environment":
            desc = "The environment to deploy on the node:<br/>" +
                "<ul>" + 
                "<li><b>raspbian_32bit</b>: 32-bit Raspbian Lite Operating System</li>" +
                "<li><b>raspbian_64bit</b>: 64-bit Raspbian Lite Operating System</li>" +
                "<li><b>raspbian_ttyd</b>: 32-bit Raspbian Lite Operating System with a shell available from web navigators</li>" +
                "<li><b>raspbian_cloud9</b>: 32-bit Raspbian Lite Operating System with the web IDE cloud9</li>" +
                "<li><b>tiny_core</b>: 32-bit tinycore v11. A minimal environment very fast to deploy</li>" +
                "<li><b>ubuntu_20.04_32bit</b>: 32-bit Ubuntu 20.04</li>" +
                "<li><b>ubuntu_20.04_64bit</b>: 64-bit Ubuntu 20.04</li>" +
                "</ul>";
            break;
        case "bin":
            desc = "Node bins are used to create node groups that will facilitate the node management.";
            break;
        case "part_size":
            desc = "The size of the main partition of the operating system. In most cases, the 'Whole' value must be selected. Only users who want to create multiple partitions should choose another value.";
            break;
        case "os_password":
            desc = "The password for the operating system, the web services (ttyd,  cloud9), the SSH connections. Leave blank to generate a different password for every node.";
            break;
        case "update_os":
            desc = "Update the operating system during the deployment.";
            break;
        default:
            desc = "Unknown property! Oooops ;)";
    }
    $(".desc").html(desc);
}
