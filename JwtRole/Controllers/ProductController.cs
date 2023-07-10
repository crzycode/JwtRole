using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtRole.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductController : ControllerBase
    {
        [Authorize(Roles ="Admin")]
        [HttpGet]
        
        public async Task<ActionResult<dynamic>> Get_data()
        {
            return "sdfs";
        }
    }
}
