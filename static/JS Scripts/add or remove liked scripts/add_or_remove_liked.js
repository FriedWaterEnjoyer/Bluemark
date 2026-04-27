// Main purpose of this function is to determine if the user wants to delete or add an item from/to their liked list - and then send a dynamic POST request to the server.py, which then will add the item to the user's liked list.

async function addToLikedMain(productId, actionType) {

// actionType determines if the user wants to delete or add an item to their liked items list. Can only be "add" or "remove" - if it's not either - then ignores it.

    if(actionType === "add") {

        try {

            const response = await fetch(

                "/like",

                {

                    method: "POST",

                    headers: {

                        "Content-Type": "application/json",

                    },

                    body: JSON.stringify({product_id: productId})

                }

            );

            if(!response.ok) {

                throw new Error("Something's wrong with adding to liked :(")

            }

        }

        catch (error) {

            console.error("Problem: ", error);

        }

    } else if (actionType === "remove") {

        try {

            const response = await fetch(

                "/remove-from-liked",

                {

                    method: "POST",

                    headers: {

                        "Content-Type": "application/json",

                    },

                    body: JSON.stringify({product_id: productId})

                }

            );

            if(!response.ok) {

                throw new Error("Something's wrong with adding to liked :(")

            }

        }

        catch (error) {

            console.error("Problem: ", error);

        }

    } else {

        // pass - since it might be a malicious command.

    }

}
