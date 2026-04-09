async function addToCart(productId) {

    try {

        const response = await fetch(

            "/add-to-cart",

            {

                method: "POST",

                headers: {

                    "Content-Type": "application/json",

                },

                body: JSON.stringify({product_id: productId})

            }

        )

        if (!response.ok) {

            throw new Error("Something's wrong with the response :(")

        }

    } catch (error) {

        console.error("Something's wrong with the request :(", error)

    }

}
