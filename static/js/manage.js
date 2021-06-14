// Display nodes and configure type buttons
$(document).ready(function () {
    var hideMe = false;
    var no_node = true;
    var activeButton = [];
    // Show the nodes according to the selected type button (raspberry, sensor, server)
    $(".type-selection").children("div").each(function(idx, typeButton) {
        var accordionId = $(typeButton).attr("id").replace("-button", "");
        var accordion = $("#" + accordionId);
        if(accordion.length > 0) {
            no_node = false;
            var bin_name = accordionId.split("-")[0];
            if(activeButton.includes(bin_name)) {
                // A button is already active, hide the nodes
                accordion.hide();
            } else {
                // Active the button and show the nodes
                $(typeButton).addClass("active");
                activeButton.push(bin_name);
            }
        } else {
            $(typeButton).addClass("disabled");
        }
    });
    if(no_node) {
        $(".manage").append("<center>" +
            "No node found from your credentials!<br/>" +
            "<a href='/user/reserve'>Go to the reservation page</a>" +
            "</center>");
    }
    updateNodeStatus();
    setInterval(updateNodeStatus, 3000);
});

// Functions
function updateNodeStatus() {
    // Get the number of nodes in the page
    $.ajax({
        type: "GET",
        url: WEBUI + "/user/node/updating",
        dataType: 'json',
        success: function (data) {
            if(data["errors"].length > 0) {
                return;
            }
            delete data["errors"];
            // Compute the number of nodes displayed in the HTML page
            var uiNbNodes = $(".card-header").length;
            // Compute the number of nodes described in the agent data
            var dataNbNodes = 0;
            for (bin in data) {
                for (nodeType in data[bin]) {
                    dataNbNodes += data[bin][nodeType].length
                }
            }
            // Reload the page to remove destroyed nodes
            if(uiNbNodes != dataNbNodes) {
                location.reload();
                return;
            }
            // Update the state
            for (bin in data) {
                for (nodeType in data[bin]) {
                    for (node of data[bin][nodeType]) {
                        osPwd = $("#" + node["name"] + "-os_password");
                        if(Object.keys(osPwd).length == 0 && "os_password" in node) {
                            // Reload the page to display the password
                            location.reload();
                        }
                        var nameDiv = $("#" + node["name"] + "-name");
                        if("percent" in node && node["state"] == "env_check") {
                            nameDiv.html(node["name"] + " - " + node["percent"] + "%");
                        } else {
                            if(nameDiv.html() != node["name"]) {
                                nameDiv.html(node["name"]);
                            }
                        }
                        var oldStatus = $("#" + node["name"] + "-state");
                        if(oldStatus.html() != node["state"]) {
                            oldStatus.html(node["state"]);
                            $("#" + node["name"] + "-circle").attr("class", "rounded-circle " + node["state"]);
                            $("#" + node["name"] + "-circle").attr("title", node["state"]);
                        }
                    }
                }
            }
        },
        error: function () {
            console.log("error: can not send the request");
        }
    });
}

function loadInfo(select) {
    var info = "";
    switch($(select).val()) {
        case "hardreboot":
            info = "Hard reboot nodes by turning off and on the power supply.";
            break;
        case "deployagain":
            info = "Deploy node environments again on nodes. All existing data will be erased.";
            break;
        case "destroy":
            info = "Free nodes by canceling reservations.";
            break;
        case "extend":
            info = "Extend reservations by postponing the end date to a later date.<br/>" +
                "The extend reconfiguration is only available <b>4 hours before</b>" +
                " the end of the reservation (maximum duration: 7 days).";
            break;
    }
    $(select).parent().parent().find("#action-desc").html(info);
}

function reconfigure(binName) {
    var nodeNames = {};
    var reconfiguration = $("#" + binName + "-select").val();
    $(".accordion:visible").each(function(idx, accordion) {
        if(accordion.id.startsWith(binName)) {
            $(accordion).find(".node-name").each(function(idx, name) {
                var imgName = name.parentNode.children[2].src.split("/");
                if(imgName[imgName.length - 1].startsWith("enabled")) {
                    var agent = $("#" + name.innerHTML + "-agent").val();
                    if(!(agent in nodeNames)) {
                        nodeNames[agent] = []
                    }
                    nodeNames[agent].push(name.innerHTML);
                }
            });
        }
    });
    if(Object.keys(nodeNames).length > 0) {
        $.ajax({
            type: "POST",
            url: WEBUI + "/user/make/exec",
            dataType: 'json',
            contentType: 'application/json',
            async: false,
            data: JSON.stringify({"reconfiguration": reconfiguration, "nodes": nodeNames}),
            success: function (data) {
                if(data["errors"].length > 0) {
                    alert("Reconfigurations error: " + data["errors"]);
                } else {
                    window.location.reload(false);
                }
            },
            error: function () {
                alert("internal error: reconfiguration is canceled");
            },
        });
    } else {
        alert("Please select nodes by ticking the checkbox on the right of the node name.")
    }
}

function destroyBin(binName) {
    var nodeNames = {};
    $(".type-selection").children("div").each(function(idx, typeButton) {
        if(typeButton.id.startsWith(binName)) {
            var accordionId = $(typeButton).attr("id").replace("-button", "");
            var accordion = $("#" + accordionId);
            if(accordion.length > 0) {
                accordion.find(".node-name").each(function(useless, node) {
                    var nodeName = node.innerHTML;
                    var agent = $("#" + nodeName + "-agent").val();
                    if(!(agent in nodeNames)) {
                        nodeNames[agent] = []
                    }
                    nodeNames[agent].push(nodeName);
                });
            }
        }
    });
    if(Object.keys(nodeNames).length > 0) {
        $.ajax({
            type: "POST",
            url: WEBUI + "/user/make/exec",
            dataType: 'json',
            contentType: 'application/json',
            async: false,
            data: JSON.stringify({"reconfiguration": "destroy", "nodes": nodeNames}),
            success: function (data) {
                if(data["errors"].length > 0) {
                    alert("Reconfigurations error: " + data["errors"]);
                } else {
                    window.location.reload(false);
                }
            },
            error: function () {
                alert("internal error: reconfiguration is canceled");
            },
        });
    }
}

function nodeSelection(typeButton) {
    if(!typeButton.classList.contains("disabled")) {
        var bin_name = $(typeButton).attr("id").split("-")[0];
        $(".type-selection").children("div").each(function(idx, allButton) {
            if(allButton.id.startsWith(bin_name)) {
                var accordionId = $(allButton).attr("id").replace("-button", "");
                if(allButton == typeButton) {
                    $("#" + accordionId).show();
                    $(allButton).addClass("active");
                } else {
                    if(!$(allButton).hasClass("disabled")) {
                        $("#" + accordionId).hide();
                        $(allButton).removeClass("active");
                    }
                }
            }
        });
    }
}

function tickNode(elem) {
    // Do not propage to not open the accordion
    event.stopPropagation();
    var img_name = elem.getAttribute("src").split("/")[3];
    if(img_name.includes("disabled")) {
        elem.setAttribute("src", "/static/img/enabled-checkbox.png");
    } else {
        elem.setAttribute("src", "/static/img/disabled-checkbox.png");
    }
}
