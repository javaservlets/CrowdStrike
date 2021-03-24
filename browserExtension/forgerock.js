//rootLibraryAppSupportCrowdStrike

document.body.style.border = "4px solid orange";
var key;
var loc;

try {
    loc = chrome.runtime.getURL('ZeroTrustAssessment/data.zta');
} catch(e) {
    console.log(e.message);
}

fetch(loc)
  .then(response => response.text())
  .then(data => {
  	key = data;
  	console.log("fetched: " + key);

    if (typeof(Storage) !== "undefined") {
      sessionStorage.setItem("jwt", key);
    } else {
      console.log("not supported: Web Storage");
    }

  });
